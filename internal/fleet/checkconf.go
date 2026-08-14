package fleet

import (
	"context"
	"errors"
	"fmt"

	"jbound/internal/logging"
	"jbound/internal/server"
	"jbound/internal/transport"
)

// ErrConfigRefused marks a change the resolver would not have loaded.
//
// It is its own class because the operator action differs from every other
// write failure: the file reached the server, the server read it back and said
// no, so the correction is to the record rather than to the connection.
var ErrConfigRefused = errors.New("the resolver refused the configuration")

// maxCheckOutput bounds how much of the check's output reaches the operator.
// A resolver that dislikes a file can say a great deal about it.
const maxCheckOutput = 400

// checkConfig validates the resolver configuration after a change is in place.
//
// The file the panel writes is included inside a server clause, so it cannot be
// validated on its own and the check names the main configuration file. That
// means the check can only run once the change is already on the target, which
// is why a refusal has to put the previous file back rather than simply
// decline to write.
//
// previous is what the file held before the change.
func (w *Writer) checkConfig(ctx context.Context, client transport.Transport,
	record server.Server, previous []byte) error {

	output, err := client.CheckConfig(ctx)
	switch {
	case errors.Is(err, transport.ErrStepSkipped):
		// A target whose sudoers rules do not reach the check yet. The change
		// stands, which is what the panel did before the check existed.
		return nil
	case err == nil:
		return nil
	}

	// Every failure rolls back, including one where the check could not run at
	// all. A refused configuration and a missing sudoers rule cannot be told
	// apart by exit code, and the safe direction is the file the resolver was
	// last known to accept. The connection test runs the same command, so a
	// missing rule is reported when the server is added.
	logging.From(ctx).Error("the resolver refused the configuration",
		"server", record.Name, "error", err, "output", foldOutput(output, maxCheckOutput))

	// The digest of what the target holds now comes from the target rather
	// than from a local hash of what was sent, so the rollback does not rest
	// on the panel and the transport agreeing about which digest is used.
	_, digest, readErr := client.ReadRecords(ctx)
	if readErr != nil {
		logging.From(ctx).Error("cannot read the file back to undo a refused change",
			"server", record.Name, "error", readErr)

		return fmt.Errorf("%w, and the previous file could not be put back: %s",
			ErrConfigRefused, foldOutput(output, maxCheckOutput))
	}

	if restoreErr := client.WriteRecords(ctx, previous, digest); restoreErr != nil {
		logging.From(ctx).Error("cannot put the previous file back",
			"server", record.Name, "error", restoreErr)

		return fmt.Errorf("%w, and the previous file could not be put back: %s",
			ErrConfigRefused, foldOutput(output, maxCheckOutput))
	}
	return fmt.Errorf("%w, so the previous file was put back: %s",
		ErrConfigRefused, foldOutput(output, maxCheckOutput))
}
