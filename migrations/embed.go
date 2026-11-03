// Package migrations holds the goose SQL files, embedded in the binary, and
// the helpers that connect to the `auth` schema and apply them.
package migrations

import "embed"

// FS contains the goose migrations at its root.
//
//go:embed *.sql
var FS embed.FS
