package sqlimpl

import "github.com/gasmod/gas"

// migrations is the store's schema, applied by gas/migrate in version order.
//
// Times are Unix milliseconds. A parent_id names either the root, whose ID is
// on the organization row, or an OU; it has no foreign key, since it points
// into one of two places. An OU keeps its path and depth, which never change:
// OUs cannot be moved.
var migrations = []gas.Migration{
	{
		Version:     "0001",
		Description: "create the organization schema",
		Up: `
CREATE TABLE organization (
	id                    TEXT PRIMARY KEY,
	feature_set           TEXT NOT NULL,
	management_account_id TEXT NOT NULL,
	root_id               TEXT NOT NULL,
	created_at            INTEGER NOT NULL
);

CREATE TABLE organizational_units (
	id        TEXT PRIMARY KEY,
	name      TEXT NOT NULL,
	parent_id TEXT NOT NULL,
	path      TEXT NOT NULL,
	depth     INTEGER NOT NULL
);
CREATE UNIQUE INDEX organizational_units_parent_name
	ON organizational_units (parent_id, name);

CREATE TABLE accounts (
	id            TEXT PRIMARY KEY,
	name          TEXT NOT NULL,
	email         TEXT NOT NULL,
	parent_id     TEXT NOT NULL,
	state         TEXT NOT NULL,
	joined_method TEXT NOT NULL,
	joined_at     INTEGER NOT NULL,
	role_name     TEXT
);
CREATE UNIQUE INDEX accounts_email ON accounts (email COLLATE NOCASE);
CREATE INDEX accounts_parent ON accounts (parent_id);

CREATE TABLE create_account_statuses (
	id             TEXT PRIMARY KEY,
	account_name   TEXT NOT NULL,
	state          TEXT NOT NULL,
	failure_reason TEXT,
	account_id     TEXT,
	requested_at   INTEGER NOT NULL,
	completed_at   INTEGER NOT NULL
);

CREATE TABLE tags (
	resource_id TEXT NOT NULL,
	key         TEXT NOT NULL,
	value       TEXT NOT NULL,
	PRIMARY KEY (resource_id, key)
);
`,
		Down: `
DROP TABLE tags;
DROP TABLE create_account_statuses;
DROP TABLE accounts;
DROP TABLE organizational_units;
DROP TABLE organization;
`,
	},
}
