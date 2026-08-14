-- Names the column after what the file holds.
--
-- The file the panel writes is a list of records, and the panel now calls it
-- that everywhere: records_path in the schema, RecordsPath in the code,
-- local_records.conf as the default name on a fresh target.
--
-- Stored paths are left exactly as they are. The value in a row is the path
-- the operator set up on that target, and the sudoers rules there name it.
-- Rewriting it here would point a working server at a file that does not
-- exist.
--
-- The column default still reads host_entries.conf, because SQLite cannot
-- change a default in place and rebuilding the table for a value nothing
-- reads would be the wrong trade. Every insert passes an explicit path that
-- ApplyDefaults has already filled, so the schema default never reaches a
-- row. The rebuild that adds the agent transport corrects it.

ALTER TABLE servers RENAME COLUMN host_entries_path TO records_path;
