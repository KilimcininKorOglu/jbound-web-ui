package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// SessionCookieName carries the session identifier. The cookie holds nothing
// else, so every session fact stays on the server.
const SessionCookieName = "unbound_web_session"

// rotateInterval controls how often a live session gets a new identifier. Five
// minutes bounds how long a stolen identifier stays useful.
const rotateInterval = 5 * time.Minute

// rotationGrace is how long the identifier a session just left behind is still
// accepted.
//
// The panel makes overlapping requests by design, so a request can be in
// flight with the previous identifier while the one beside it rotates. The
// window covers that race and nothing more: rotation exists to bound how long
// a stolen identifier stays useful, and a long grace would undo it.
const rotationGrace = 10 * time.Second

// Session states reported by Load. The caller turns each into a redirect or a
// plain rejection, so the reasons stay distinct here.
var (
	ErrNoSession           = errors.New("no session")
	ErrSessionExpired      = errors.New("session expired")
	ErrFingerprintMismatch = errors.New("session fingerprint mismatch")
)

// Session is one logged in browser.
type Session struct {
	ID            string
	UID           int
	Username      string
	Role          string
	Fingerprint   string
	CSRFToken     string
	LastActive    time.Time
	RegeneratedAt time.Time
	CreatedAt     time.Time
}

// IsAdmin reports whether the session may reach the admin only areas.
func (s Session) IsAdmin() bool { return s.Role == RoleAdmin }

// SessionSummary is what one account has open, as a page may see it.
//
// No identifier is carried. The identifier is the credential the browser
// presents, so a view that held one would be handing it out.
type SessionSummary struct {
	UID        int
	Username   string
	Role       string
	Count      int
	FirstSeen  time.Time
	LastActive time.Time
}

// IsAdmin reports whether the account holds the admin role.
func (s SessionSummary) IsAdmin() bool { return s.Role == RoleAdmin }

// SessionRepository stores sessions. Rotation is one operation rather than a
// delete and an insert, because a crash between the two would log the user out.
type SessionRepository interface {
	Create(ctx context.Context, session Session) error
	Find(ctx context.Context, id string, rotatedSince time.Time) (Session, error)
	Touch(ctx context.Context, id string, at time.Time) error
	Rotate(ctx context.Context, oldID, newID string, at time.Time) (bool, error)
	Delete(ctx context.Context, id string) error
	ListLive(ctx context.Context, since time.Time) ([]SessionSummary, error)
	DeleteByUIDExcept(ctx context.Context, uid int, keepID string) (int, error)
	DeleteAllExcept(ctx context.Context, keepID string) (int, error)
}

// SessionManager applies the session rules to HTTP requests.
type SessionManager struct {
	repo SessionRepository

	// idle is read on every request rather than held as a value, so a change
	// made on the settings page applies to the sessions that are already open.
	idle func() time.Duration

	// lifetime bounds a session however active it is. Without it a browser
	// that is used every day never signs out, which is what turns a stolen
	// laptop into a permanent session.
	lifetime func() time.Duration

	cookieSecure bool
	// now is replaceable so tests can move past the timeout without sleeping.
	now func() time.Time
}

// NewSessionManager builds the manager.
func NewSessionManager(repo SessionRepository, idle, lifetime func() time.Duration,
	cookieSecure bool) *SessionManager {

	return &SessionManager{
		repo:         repo,
		idle:         idle,
		lifetime:     lifetime,
		cookieSecure: cookieSecure,
		now:          time.Now,
	}
}

// Start creates a session for an authenticated user and sets the cookie.
//
// The identifier is new, so a session fixation attempt that planted a cookie
// before the login gains nothing.
func (m *SessionManager) Start(ctx context.Context, w http.ResponseWriter,
	r *http.Request, user User) (Session, error) {

	id, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	csrfToken, err := randomToken()
	if err != nil {
		return Session{}, err
	}

	now := m.now().UTC()
	session := Session{
		ID:            id,
		UID:           user.UID,
		Username:      user.Username,
		Role:          user.Role,
		Fingerprint:   Fingerprint(r),
		CSRFToken:     csrfToken,
		LastActive:    now,
		RegeneratedAt: now,
		CreatedAt:     now,
	}

	if err := m.repo.Create(ctx, session); err != nil {
		return Session{}, fmt.Errorf("cannot create the session: %w", err)
	}
	m.setCookie(w, session.ID)
	return session, nil
}

// Load returns the session of the current request.
//
// It also enforces the timeout, the fingerprint and the rotation interval, so
// no caller can forget one of them.
func (m *SessionManager) Load(ctx context.Context, w http.ResponseWriter,
	r *http.Request) (Session, error) {

	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return Session{}, ErrNoSession
	}

	now := m.now().UTC()

	session, err := m.repo.Find(ctx, cookie.Value, now.Add(-rotationGrace))
	if err != nil {
		// An unknown identifier is indistinguishable from an expired one that
		// the cleanup loop already removed.
		m.clearCookie(w)
		return Session{}, ErrNoSession
	}

	// The identifier the row carries is not the one that arrived, so a request
	// beside this one rotated a moment ago. Its response already handed the
	// browser the new identifier.
	rotatedBySibling := session.ID != cookie.Value

	if now.Sub(session.LastActive) > m.idle() {
		m.destroy(ctx, w, session.ID)
		return Session{}, ErrSessionExpired
	}

	// The absolute bound. A session that is used all day still ends, so a
	// browser somebody walked away from cannot stay signed in for ever.
	if now.Sub(session.CreatedAt) > m.lifetime() {
		m.destroy(ctx, w, session.ID)
		return Session{}, ErrSessionExpired
	}

	// Constant time, because the fingerprint is derived from data the client
	// controls and a timing signal would help an attacker forge it.
	if !hmac.Equal([]byte(session.Fingerprint), []byte(Fingerprint(r))) {
		m.destroy(ctx, w, session.ID)
		return Session{}, ErrFingerprintMismatch
	}

	if !rotatedBySibling && now.Sub(session.RegeneratedAt) >= rotateInterval {
		newID, err := randomToken()
		if err != nil {
			return Session{}, err
		}

		rotated, err := m.repo.Rotate(ctx, session.ID, newID, now)
		if err != nil {
			return Session{}, fmt.Errorf("cannot rotate the session: %w", err)
		}
		if rotated {
			session.ID = newID
			session.RegeneratedAt = now
			session.LastActive = now
			m.setCookie(w, newID)
			return session, nil
		}
		// A request beside this one rotated first. Both hold the same live
		// session, and the cookie the browser keeps is the one that request
		// set, so this response leaves it alone.
		return session, nil
	}

	if err := m.repo.Touch(ctx, session.ID, now); err != nil {
		return Session{}, fmt.Errorf("cannot touch the session: %w", err)
	}
	session.LastActive = now
	return session, nil
}

// Destroy ends one session.
//
// The identifier comes from the loaded session rather than from the request
// cookie, because Load rotates it on the same request and the request object
// still carries the value the browser sent.
func (m *SessionManager) Destroy(ctx context.Context, w http.ResponseWriter,
	sessionID string) error {

	m.clearCookie(w)
	if sessionID == "" {
		return nil
	}
	if err := m.repo.Delete(ctx, sessionID); err != nil {
		return fmt.Errorf("cannot delete the session: %w", err)
	}
	return nil
}

// Live summarises the accounts that have a session open.
//
// The idle timeout is read here rather than passed in, so no caller can decide
// on its own what counts as live and show sessions nobody can use.
func (m *SessionManager) Live(ctx context.Context) ([]SessionSummary, error) {
	summaries, err := m.repo.ListLive(ctx, m.now().UTC().Add(-m.idle()))
	if err != nil {
		return nil, fmt.Errorf("cannot list the sessions: %w", err)
	}
	return summaries, nil
}

// RevokeAccount ends every session of one account and reports how many went.
//
// keepID stays alive. It is the caller's own session, which would otherwise be
// closed by the same click that closed the attacker's and leave nobody able to
// see the result.
func (m *SessionManager) RevokeAccount(ctx context.Context, uid int, keepID string) (int, error) {
	removed, err := m.repo.DeleteByUIDExcept(ctx, uid, keepID)
	if err != nil {
		return 0, fmt.Errorf("cannot revoke the sessions of an account: %w", err)
	}
	return removed, nil
}

// RevokeAll ends every session on the panel but the caller's own.
func (m *SessionManager) RevokeAll(ctx context.Context, keepID string) (int, error) {
	removed, err := m.repo.DeleteAllExcept(ctx, keepID)
	if err != nil {
		return 0, fmt.Errorf("cannot revoke the sessions: %w", err)
	}
	return removed, nil
}

// destroy removes a rejected session. The error is swallowed on purpose: the
// caller is already rejecting the request, and the cleanup loop removes the row
// later anyway.
func (m *SessionManager) destroy(ctx context.Context, w http.ResponseWriter, id string) {
	m.clearCookie(w)
	_ = m.repo.Delete(ctx, id)
}

func (m *SessionManager) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		// The cookie outlives the browser window and expires with the session
		// lifetime. The server side rules still decide: the cookie only stops
		// the browser from offering an identifier that cannot work any more.
		MaxAge: int(m.lifetime().Seconds()),
	})
}

func (m *SessionManager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// Fingerprint binds a session to the client that created it.
//
// The address is the key and the user agent is the message. Only the address
// is used, not the source port, because a new connection gets a new port and
// would otherwise drop the session.
func Fingerprint(r *http.Request) string {
	key := sha256.Sum256([]byte(ClientIP(r)))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(r.UserAgent()))
	return hex.EncodeToString(mac.Sum(nil))
}

// ClientIP reports the address the request arrived from.
//
// Forwarding headers are ignored. They are client supplied, so trusting them
// would let anyone reset the login rate limit and forge a session fingerprint.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// randomToken returns 32 random bytes in hex.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("cannot read random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
