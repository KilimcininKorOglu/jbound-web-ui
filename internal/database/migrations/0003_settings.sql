-- Panel settings an operator can change without a restart.
--
-- Key and value rather than one column per setting. The settings page is built
-- from a registry in the code, so a new setting is one entry there and needs no
-- migration. A missing row means the registry default, which is why an empty
-- table behaves exactly like the panel did before this migration.
--
-- Only values that are safe to change at runtime live here. Anything that
-- decides who may sign in or which binary runs stays in the environment, so a
-- write to this table cannot widen a privilege.

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);
