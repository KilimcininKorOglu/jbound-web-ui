-- Adds the command that makes the resolver read the records file.
--
-- Writing records to a file the main configuration never includes is the one
-- failure the rest of the path cannot see. The write lands, unbound-checkconf
-- accepts the configuration because nothing in it is wrong, the reload
-- succeeds, and not a single record resolves. Nothing reports anything.
--
-- The command carries no arguments. Both paths, the records file and the main
-- configuration, are written into the script on the target when it is set up.
-- A command that took a path from the panel would turn every managed server
-- into somewhere the panel can write any file it names, which is a far larger
-- thing than the one this repairs.
--
-- Existing rows are filled with the default, the same way the reload ladder
-- filled its three. A server prepared with an older setup script has no such
-- script and no sudoers rule for it, so the command fails and the step is
-- reported rather than run. Re-running the setup script there installs both.

ALTER TABLE servers ADD COLUMN ensure_include_cmd TEXT NOT NULL DEFAULT '';

UPDATE servers SET
    ensure_include_cmd = 'sudo /usr/local/sbin/jbound-ensure-include'
WHERE ensure_include_cmd = '';
