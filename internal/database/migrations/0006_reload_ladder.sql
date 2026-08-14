-- Adds the three commands a change now runs beside the reload.
--
-- check_conf_cmd validates the resolver configuration after the file is in
-- place and before the resolver is asked to read it. The included file cannot
-- be validated on its own, because it sits inside a server clause, so the
-- command names the main configuration file.
--
-- reload_fallback_cmd and restart_cmd are the second and third rungs of the
-- reload. A reload that fails, or that leaves the resolver stopped, escalates
-- rather than reporting success.
--
-- Existing rows are filled with the defaults, because ApplyDefaults only runs
-- when a record is created. reload_cmd is left as it stands: it is the command
-- the operator entered and the sudoers rule on that target names it.

ALTER TABLE servers ADD COLUMN check_conf_cmd TEXT NOT NULL DEFAULT '';
ALTER TABLE servers ADD COLUMN reload_fallback_cmd TEXT NOT NULL DEFAULT '';
ALTER TABLE servers ADD COLUMN restart_cmd TEXT NOT NULL DEFAULT '';

UPDATE servers SET
    check_conf_cmd = 'sudo /usr/sbin/unbound-checkconf /etc/unbound/unbound.conf',
    reload_fallback_cmd = 'sudo /usr/sbin/service unbound reload',
    restart_cmd = 'sudo /usr/sbin/service unbound restart';
