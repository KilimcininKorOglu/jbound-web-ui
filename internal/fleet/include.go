package fleet

import (
	"context"
	"errors"
	"strings"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/logging"
	"jbound/internal/server"
	"jbound/internal/transport"
)

// writeRecords sends the file to the target with its clause header in place.
//
// Every write goes through here, including the one that undoes a refused
// change. A rollback that put back a file without the header would leave a
// target whose main configuration includes something the resolver cannot
// load, which is worse than the change that was refused.
func writeRecords(ctx context.Context, client transport.Transport,
	data []byte, digest string) error {

	return client.WriteRecords(ctx, dnsfile.EnsureHeader(data), digest)
}

// ensureInclude makes the resolver read the records file before the panel
// changes it.
//
// This is the one failure nothing downstream catches. A main configuration
// with no include line for the records file takes every write, passes every
// configuration check, reloads without complaint, and answers none of the
// records. The panel would show a server that is up to date and the resolver
// would be serving nothing the operator entered.
//
// It runs before the read rather than after the write, so the file the panel
// then reads already carries its clause header. A rollback puts that same
// content back, which keeps the configuration loadable whichever way it ends.
//
// A failure here does not stop the change. The write is still correct, and a
// target prepared with an older setup script has neither the command nor the
// sudoers rule for it. Refusing every change on those servers would be a far
// worse answer than writing the file and saying what could not be checked.
func (w *Writer) ensureInclude(ctx context.Context, client transport.Transport,
	actor server.Actor, record server.Server) {

	output, err := client.EnsureInclude(ctx)
	switch {
	case errors.Is(err, transport.ErrStepSkipped):
		// The server record names no command, which is a target prepared
		// before this step existed.
		return
	case err != nil:
		logging.From(ctx).Warn("cannot confirm the resolver reads the records file",
			"server", record.Name, "error", err)
		return
	}

	if strings.TrimSpace(output) != transport.IncludeAdded {
		return
	}

	// The panel just changed the main resolver configuration of a managed
	// server. That is its own event rather than a footnote on the record
	// change that happened to trigger it, so it gets its own row.
	logging.From(ctx).Warn("the resolver configuration was missing its include line",
		"server", record.Name)

	serverID := record.ID
	_ = w.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		ServerID:   &serverID,
		ServerName: record.Name,
		Action:     audit.ActionConfigInclude,
		Details: "The main resolver configuration of " + record.Name +
			" did not include the records file, so the panel added the line.",
		IPAddress: actor.IPAddress,
	})
}
