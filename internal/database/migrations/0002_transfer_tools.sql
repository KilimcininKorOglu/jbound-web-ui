-- Replaces the cat path with a sha256 path in the server records.
--
-- The read command no longer pipes cat into base64. A shell pipeline reports
-- the status of its last command, so a cat that could not open the file exited
-- unnoticed and the read returned an empty file. base64 now opens the file
-- itself, which makes a failure a failure.
--
-- The write command gained a digest step. Joining tee and mv with && gates the
-- move on the status of tee, and tee is content to write a stream that was cut
-- short, so a connection lost halfway through would have truncated the target
-- file. The panel now checks the digest of the temporary file before it is
-- moved into place.

ALTER TABLE servers ADD COLUMN sha256_path TEXT NOT NULL DEFAULT '/usr/bin/sha256sum';

ALTER TABLE servers DROP COLUMN cat_path;
