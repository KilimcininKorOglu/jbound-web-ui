package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// clauseHeader opens the Unbound clause the records belong to.
//
// A file of bare local-data lines is only legal inside a server clause. Its own
// header makes it loadable wherever the include line ends up, which is what
// lets the include go at the end of the main configuration instead of
// somewhere the agent would have to reason about.
const clauseHeader = "server:"

// recordsMode is what the file is left as. The panel reads it over this agent
// rather than off the disk, but a resolver that drops privileges still has to
// open it.
const recordsMode = 0o644

// readRecords returns the file and its digest.
//
// A file that is not there yet is an empty one rather than a failure. That is
// what a freshly installed target holds, and refusing to read it would make
// the first connection test fail on a host where nothing is wrong.
func (a *Agent) readRecords() ([]byte, string, error) {
	data, err := os.ReadFile(a.cfg.RecordsPath)
	if os.IsNotExist(err) {
		return nil, digestOf(nil), nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("cannot read %s: %w", a.cfg.RecordsPath, err)
	}
	return data, digestOf(data), nil
}

// writeRecords replaces the file, refusing when it changed underneath.
//
// expect is the digest the panel last read. An empty one skips the comparison,
// which is a first write to a target the panel has not read yet.
//
// The path is the one from the configuration and nowhere else. Every caller
// reaches this through an endpoint that takes no path at all.
func (a *Agent) writeRecords(data []byte, expect string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, digest, err := a.readRecords()
	if err != nil {
		return err
	}
	if expect != "" && expect != digest {
		return errConflict
	}
	return replaceFile(a.cfg.RecordsPath, data, true)
}

// replaceFile writes the content beside the target and moves it into place.
//
// Same directory, so the move is atomic and a resolver reading the file never
// sees half of one. The temporary name is fixed rather than random for the
// same reason the ssh path fixes it: a leftover from a killed process is one
// file to find rather than a directory that fills up.
//
// A rename replaces the inode, so the owner, the group and the mode of the
// file that was there are gone unless they are carried over. They are carried
// over here: a file this agent rewrote should look to every other tool exactly
// like the file it replaced.
//
// keepReadable is for the records file, which a resolver that dropped
// privileges still has to open. The main configuration is not this agent's
// file to normalise, so it keeps whatever mode it had.
func replaceFile(path string, data []byte, keepReadable bool) error {
	dir, name := filepath.Split(path)
	staging := filepath.Join(dir, "."+name+".tmp")

	mode, uid, gid := previousOwnership(path, keepReadable)

	// 0755 is the mode /etc/unbound carries on a Debian host. The resolver
	// reads that directory as root and the panel account has to list it, so
	// tightening it here would break the software this manages.
	// #nosec G301 -- the resolver owns this directory and needs it listable.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}

	// The staging name is derived from the configured records path, which only
	// root writes. No request names a file here.
	// #nosec G304 -- the path is configuration, never request input.
	file, err := os.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, recordsMode)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", staging, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(staging)
		return fmt.Errorf("cannot write %s: %w", staging, err)
	}

	// The bytes have to be on the disk before the rename. A crash between the
	// two would otherwise leave the resolver including an empty file.
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(staging)
		return fmt.Errorf("cannot flush %s: %w", staging, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("cannot finish %s: %w", staging, err)
	}

	// The mode is set explicitly rather than left to the umask, because the
	// umask of whatever started this process is not something to inherit for a
	// file a resolver has to open.
	if err := os.Chmod(staging, mode); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("cannot set the mode on %s: %w", staging, err)
	}
	restoreOwnership(staging, uid, gid)

	if err := os.Rename(staging, path); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("cannot move %s into place: %w", path, err)
	}
	return nil
}

// previousOwnership reports what the file being replaced looked like.
//
// A file that is not there yet has no previous anything, and the records mode
// is what a new one gets.
func previousOwnership(path string, keepReadable bool) (os.FileMode, int, int) {
	info, err := os.Stat(path)
	if err != nil {
		return recordsMode, -1, -1
	}

	mode := info.Mode().Perm()
	if keepReadable && mode&0o044 == 0 {
		// Somebody tightened it to where the resolver cannot open it. Carrying
		// that over would keep a file nothing can read, so the guarantee wins
		// over the preservation here.
		mode = recordsMode
	}

	uid, gid := -1, -1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(stat.Uid), int(stat.Gid)
	}
	return mode, uid, gid
}

// restoreOwnership puts the replacement under the account that owned the file.
//
// Best effort, and deliberately quiet about failing. A process that is not root
// cannot give a file away, so an agent running under its own account cannot
// take one back to root however much it would like to. The group is what is
// left to carry over there, and setup-agent.sh makes the two files it manages
// the agent's own so that nothing drifts on the first write.
func restoreOwnership(path string, uid, gid int) {
	if uid < 0 && gid < 0 {
		return
	}
	if os.Chown(path, uid, gid) == nil {
		return
	}
	_ = os.Chown(path, -1, gid)
}

// ensureInclude makes the resolver read the records file, and says what it had
// to do.
//
// This is the failure nothing else catches. A main configuration without an
// include line takes every write, passes unbound-checkconf because nothing in
// it is wrong, reloads without complaint, and answers none of the records.
//
// It runs at startup and whenever the panel asks. Both paths come from the
// configuration, never from a request.
func (a *Agent) ensureInclude() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.ensureHeader(); err != nil {
		return "", err
	}

	included, err := includesRecords(a.cfg.MainConfig, a.cfg.RecordsPath)
	if err != nil {
		return "", err
	}
	if included {
		return "ok", nil
	}

	main, err := os.ReadFile(a.cfg.MainConfig)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", a.cfg.MainConfig, err)
	}
	if len(main) > 0 && !strings.HasSuffix(string(main), "\n") {
		main = append(main, '\n')
	}
	main = append(main, []byte("include: "+a.cfg.RecordsPath+"\n")...)

	if err := replaceFile(a.cfg.MainConfig, main, false); err != nil {
		return "", err
	}
	return "added", nil
}

// ensureHeader puts the clause header at the top of the records file, creating
// the file when it is not there. The caller holds the lock.
func (a *Agent) ensureHeader() error {
	data, _, err := a.readRecords()
	if err != nil {
		return err
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(line) == clauseHeader {
			return nil
		}
	}
	return replaceFile(a.cfg.RecordsPath, append([]byte(clauseHeader+"\n"), data...), true)
}

// includesRecords reports whether the main configuration reads the file.
//
// The comparison is against the whole line rather than a substring, so an
// include of a different file whose name contains this one does not count as
// this one.
func includesRecords(mainConfig, recordsPath string) (bool, error) {
	// #nosec G304 -- the path is configuration, never request input.
	file, err := os.Open(mainConfig)
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", mainConfig, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, found := strings.CutPrefix(line, "include:")
		if !found {
			continue
		}
		// Unbound accepts the path quoted or bare, and operators write both.
		named := strings.Trim(strings.TrimSpace(rest), `"`)
		if named == recordsPath {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("cannot read %s: %w", mainConfig, err)
	}
	return false, nil
}

// digestOf renders the SHA-256 of the file the way the panel compares it.
func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
