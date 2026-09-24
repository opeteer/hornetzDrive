package ztatic

import "embed"

//go:embed data/migrations_sqlite3/*.sql data/migrations_postgres/*.sql
var MigrationFS embed.FS

//go:embed assets/*
var AssetsFS embed.FS
