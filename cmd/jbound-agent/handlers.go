package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"jbound/internal/agentapi"
)

// Agent answers the panel.
type Agent struct {
	cfg   *Config
	token string
	log   *slog.Logger

	// mu serialises everything that touches a file. Two panels writing at once
	// would otherwise each read, each change and each write, and one of the two
	// changes would be gone.
	mu sync.Mutex
}

// NewAgent reads the token and prepares the handler.
func NewAgent(cfg *Config, token string, log *slog.Logger) *Agent {
	return &Agent{cfg: cfg, token: token, log: log}
}

// Routes builds the mux.
//
// Every path is a constant from the protocol package, so the set of things this
// agent will do is fixed at compile time rather than assembled from anything a
// caller sends.
func (a *Agent) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+agentapi.PathInfo, a.handleInfo)
	mux.HandleFunc("GET "+agentapi.PathRecords, a.handleReadRecords)
	mux.HandleFunc("PUT "+agentapi.PathRecords, a.handleWriteRecords)
	mux.HandleFunc("POST "+agentapi.PathEnsureInclude, a.handleEnsureInclude)
	mux.HandleFunc("POST "+agentapi.PathCheckConf, a.step(func(c *Config) Command { return c.CheckConfCmd }))
	mux.HandleFunc("POST "+agentapi.PathReload, a.step(func(c *Config) Command { return c.ReloadCmd }))
	mux.HandleFunc("POST "+agentapi.PathReloadBack, a.step(func(c *Config) Command { return c.ReloadFallbackCmd }))
	mux.HandleFunc("POST "+agentapi.PathRestart, a.step(func(c *Config) Command { return c.RestartCmd }))
	mux.HandleFunc("GET "+agentapi.PathStatus, a.handleStatus)

	return a.authenticated(mux)
}

// authenticated refuses anything without the token.
//
// It wraps the mux rather than each handler, so a route added later cannot be
// left unprotected by forgetting a line.
func (a *Agent) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offered, found := strings.CutPrefix(
			r.Header.Get("Authorization"), agentapi.AuthScheme+" ")

		// Constant time, and against a value of the same length either way. A
		// comparison that returned early would let a caller find the token one
		// character at a time.
		if !found || subtle.ConstantTimeCompare(
			[]byte(strings.TrimSpace(offered)), []byte(a.token)) != 1 {

			// The address and nothing else. What was offered is not written
			// down: a token in a log file is a token to rotate, and a near
			// miss in one is worse than useless.
			a.log.Warn("a request arrived without the right token",
				"remote", r.RemoteAddr, "path", r.URL.Path)

			a.fail(w, http.StatusUnauthorized, agentapi.ClassAuth,
				"the token is not the one this agent expects")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleInfo says what this agent manages.
//
// The path travels from here to the panel and never the other way. An agent
// that took the path from a request would be a way to write any file on this
// host, which is a far larger thing than anything else here.
func (a *Agent) handleInfo(w http.ResponseWriter, _ *http.Request) {
	included, err := includesRecords(a.cfg.MainConfig, a.cfg.RecordsPath)
	if err != nil {
		a.log.Error("cannot read the main configuration", "error", err)
	}

	a.answer(w, agentapi.Info{
		Version:     agentapi.Version,
		RecordsPath: a.cfg.RecordsPath,
		IncludeOK:   err == nil && included,
		Steps: agentapi.Steps{
			CheckConf:      a.cfg.CheckConfCmd.Configured(),
			Reload:         a.cfg.ReloadCmd.Configured(),
			ReloadFallback: a.cfg.ReloadFallbackCmd.Configured(),
			Restart:        a.cfg.RestartCmd.Configured(),
			Status:         a.cfg.StatusCmd.Configured(),
		},
	})
}

func (a *Agent) handleReadRecords(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	data, digest, err := a.readRecords()
	a.mu.Unlock()

	if err != nil {
		a.log.Error("cannot read the records file", "error", err)
		a.fail(w, http.StatusInternalServerError, agentapi.ClassInternal,
			"the records file could not be read")
		return
	}

	a.answer(w, agentapi.Records{
		Content: base64.StdEncoding.EncodeToString(data),
		SHA256:  digest,
	})
}

func (a *Agent) handleWriteRecords(w http.ResponseWriter, r *http.Request) {
	var request agentapi.WriteRequest
	if !a.read(w, r, &request) {
		return
	}

	data, err := base64.StdEncoding.DecodeString(request.Content)
	if err != nil {
		a.fail(w, http.StatusBadRequest, agentapi.ClassBadInput,
			"the content is not base64")
		return
	}

	// The file is read by the resolver as part of its own configuration, so
	// what may be written into it is records and nothing else.
	if err := validateContent(data); err != nil {
		a.log.Warn("a write carried something that is not a record", "error", err)
		a.fail(w, http.StatusBadRequest, agentapi.ClassBadInput, err.Error())
		return
	}

	// Nothing in the request said where this goes. The file is the one the
	// configuration on this host names, and there is no way to ask for
	// another.
	switch err := a.writeRecords(data, request.ExpectSHA256); {
	case errors.Is(err, errConflict):
		a.fail(w, http.StatusConflict, agentapi.ClassConflict,
			"the file changed since it was read")
	case err != nil:
		a.log.Error("cannot write the records file", "error", err)
		a.fail(w, http.StatusInternalServerError, agentapi.ClassInternal,
			"the records file could not be written")
	default:
		a.answer(w, agentapi.CommandResult{Output: "written"})
	}
}

func (a *Agent) handleEnsureInclude(w http.ResponseWriter, _ *http.Request) {
	output, err := a.ensureInclude()
	if err != nil {
		a.log.Error("cannot confirm the resolver reads the records file", "error", err)
		a.fail(w, http.StatusInternalServerError, agentapi.ClassInternal,
			"the main configuration could not be read or written")
		return
	}
	if output == "added" {
		a.log.Warn("the main configuration did not include the records file, so it was added",
			"main", a.cfg.MainConfig, "records", a.cfg.RecordsPath)
	}
	a.answer(w, agentapi.CommandResult{Output: output})
}

// step builds a handler for one configured command.
//
// The command is chosen by which route was matched, never by anything in the
// request. A caller can ask for a reload; it cannot say what a reload is.
func (a *Agent) step(pick func(*Config) Command) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		output, err := a.run(r.Context(), pick(a.cfg))
		a.answerStep(w, output, err)
	}
}

func (a *Agent) handleStatus(w http.ResponseWriter, r *http.Request) {
	active, detail, err := a.serviceStatus(r.Context())
	if errors.Is(err, errSkipped) {
		a.fail(w, agentapi.StatusStepSkipped, agentapi.ClassSkipped,
			"this agent has no status command")
		return
	}
	if err != nil {
		a.log.Error("cannot read the resolver status", "error", err)
		a.fail(w, http.StatusInternalServerError, agentapi.ClassInternal,
			"the resolver status could not be read")
		return
	}
	a.answer(w, agentapi.StatusResult{Active: active, Detail: detail})
}

// answerStep turns the outcome of one command into an answer.
func (a *Agent) answerStep(w http.ResponseWriter, output string, err error) {
	var refused *commandError

	switch {
	case errors.Is(err, errSkipped):
		a.fail(w, agentapi.StatusStepSkipped, agentapi.ClassSkipped,
			"this agent has no command for that step")
	case errors.As(err, &refused):
		// The output rather than a summary. The resolver already said what is
		// wrong with the configuration, and the panel shows it to whoever made
		// the change.
		a.fail(w, http.StatusUnprocessableEntity, agentapi.ClassCommand, refused.Error())
	case err != nil:
		a.fail(w, http.StatusInternalServerError, agentapi.ClassInternal, err.Error())
	default:
		a.answer(w, agentapi.CommandResult{Output: output})
	}
}

// read decodes a request body, bounded.
//
// How much memory this host sets aside is not a decision the caller makes. The
// agent runs as root on a resolver, and a body nobody bounded is the cheapest
// way to stop one.
func (a *Agent) read(w http.ResponseWriter, r *http.Request, into any) bool {
	body := http.MaxBytesReader(w, r.Body, agentapi.MaxBodyBytes)

	if err := json.NewDecoder(body).Decode(into); err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			a.fail(w, http.StatusRequestEntityTooLarge, agentapi.ClassBadInput,
				"the request is larger than this agent accepts")
			return false
		}
		a.fail(w, http.StatusBadRequest, agentapi.ClassBadInput,
			"the request will not parse")
		return false
	}

	// A second value in the same body would mean the caller sent something
	// this agent does not understand, and guessing which one was meant is
	// worse than saying so.
	if err := json.NewDecoder(body).Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		a.fail(w, http.StatusBadRequest, agentapi.ClassBadInput,
			"the request carries more than one value")
		return false
	}
	return true
}

func (a *Agent) answer(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		a.log.Error("cannot write the answer", "error", err)
	}
}

func (a *Agent) fail(w http.ResponseWriter, status int, class, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(agentapi.Error{
		Class: class, Message: message}); err != nil {
		a.log.Error("cannot write the failure", "error", err)
	}
}

// ensureIncludeAtStart runs the repair once, when the agent comes up.
//
// A host that was set up correctly says ok and nothing is written. One whose
// main configuration lost the line is corrected before the panel ever asks,
// which is the difference between a resolver that answers and one that
// silently does not.
func (a *Agent) ensureIncludeAtStart() {
	output, err := a.ensureInclude()
	if err != nil {
		a.log.Error("cannot confirm the resolver reads the records file", "error", err)
		return
	}
	if output == "added" {
		a.log.Warn("the main configuration did not include the records file, so it was added",
			"main", a.cfg.MainConfig, "records", a.cfg.RecordsPath)
	}
}
