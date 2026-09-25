# Hornetz Drive

[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Security](https://img.shields.io/badge/Security-Zero--Trust-red?style=flat-square&logo=shield)](https://github.com/opeteer/hornetzDrive)
[![Architecture](https://img.shields.io/badge/Architecture-HOTW-success?style=flat-square)](https://github.com/opeteer/hornetzDrive)
[![Storage](https://img.shields.io/badge/Storage-CAS--Deduplicated-orange?style=flat-square)](https://github.com/opeteer/hornetzDrive)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

**Hornetz Drive** is a high-performance, zero-trust, enterprise-grade encrypted cloud storage and asset management engine built with **Go 1.26+** and **Echo v5**. It is powered by the **HOTW (HTML Over The Wire)** stack: **Templ**, **Hotwire (Turbo 8)**, **Alpine.js**, and **Server-Sent Events (SSE)**.

Hornetz Drive provides client & server streaming AES-256-GCM encryption, content-addressable storage (CAS) with 0-second file deduplication, anti-forensic path obfuscation via the Chitin Shuffler, resumable chunked uploads, and an emergency Stinger Panic Purge protocol—all bundled inside a single, zero-dependency static binary.

---

## Key Features & Architecture Pillars

### 1. Zero-Trust Security & Encryption Engine
* **AES-256-GCM Chunked Stream Encryption:** `EncryptStream` and `DecryptStream` handle continuous block-by-block data streams (`[4-byte length][12-byte nonce][ciphertext + tag]`), preventing full-file memory buffering.
* **Argon2id Key Derivation:** Master Encryption Key (MEK) derived securely using Argon2id (`time=3, memory=64MB, threads=4`).
* **Stinger Panic Purge:** One-touch emergency endpoint (`/api/purge`) that instantly obliterates RAM keys and overwrites physical disk storage with cryptographic random bytes (`os.urandom`) before deletion.

### 2. Content-Addressable Storage (CAS) & Deduplication
* **0-Second Deduplication:** Physical storage is indexed by SHA-256 content hashes. Identical file contents uploaded by multiple users consume zero additional disk space.
* **Path Sharding:** Files are stored in deep directory shards (`storage/cas/ab/cd/hash...`) to prevent filesystem performance bottlenecks under massive file volume.
* **Chitin Shuffler:** Background anti-forensics process that periodically rotates path shards and obfuscates filesystem access timestamps (`mtime`) to thwart access pattern analysis.

### 3. Resumable Chunked Upload Engine
* **Session-Managed Multipart Uploads:** Supports large file uploads fragmented into discrete binary chunks via `/upload/init`, `PUT /upload/:session_id`, and `GET /upload/:session_id`.
* **Stateful Assembly & Integrity Verification:** Upload progress is tracked in-memory, verified against expected file sizes, and moved atomically into CAS upon completion.

### 4. HOTW Real-Time Dashboard (Templ + Turbo + Alpine.js)
* **Type-Safe Templ Views:** Rendered directly into server response buffers for maximum throughput.
* **Zero-JS Realtime Event Streams:** Server-Sent Events (SSE) stream Turbo Stream DOM mutations (`append`, `update`, `remove`) directly to the client without page refreshes.
* **Reactive Micro-Interactions:** Alpine.js client-side reactivity and state preservation.

### 5. Multi-Database Engine & Embedded Migrations
* **SQLite3 (WAL Mode) & PostgreSQL Support:** Configurable through environment variables (`DB_DRIVER`, `DB_DSN`).
* **Embedded Schema Migrations:** Database migrations (`data/migrations_sqlite3`, `data/migrations_postgres`) executed automatically at startup via embedded Goose (`embed.FS`).

---

## Architecture & Directory Layout

```text
hornetzDrive/
├── cmd/
│   ├── hornetz/          # Main Hornetz Drive application entry point (main.go)
│   └── ztatic/           # Unified CLI tool for scaffolding & building
├── internal/
│   ├── auth/             # Session management & Vault Key middleware
│   ├── controllers/      # Handlers: FileController, UploadController, SecurityController
│   ├── crypto/           # AES-256-GCM streaming encryption & Argon2id key derivation
│   ├── storage/          # CAS engine & Chitin Shuffler background worker
│   ├── ui/               # Templ components and layouts (dashboard, layout)
│   └── upload/           # Resumable chunked upload session manager
├── data/
│   ├── db.go             # Database engine initializer & generic transaction wrapper
│   ├── migrate.go        # Embedded Goose schema migration driver
│   ├── migrations_postgres/
│   └── migrations_sqlite3/
├── assets/               # CSS, JS, and static frontend resources
├── echo/                 # Embedded Echo v5 web framework engine
├── storage/              # Runtime CAS storage & temporary upload buffers
├── Dockerfile            # Multi-stage Alpine container build specification
├── docker-compose.yml    # Full-stack orchestrator (Web + Postgres + Redis)
├── Makefile              # Project build & Templ code generation targets
└── go.mod                # Module definition & dependency management
```

---

## API Reference Summary

### File Management API
* `GET /api/files` - Retrieve user file listing (JSON).
* `GET /api/folders` - Retrieve folder structure (JSON).
* `GET /api/files/:id/download` - Stream and decrypt file content on-the-fly.
* `DELETE /api/files/:id` - Delete user file reference.

### Protected Resumable Upload API
* `POST /upload/init` - Initialize an upload session (`owner_id`, `filename`, `size`, `mime_type`).
* `PUT /upload/:session_id` - Upload binary file chunk.
* `GET /upload/:session_id` - Check current upload session status & byte progress.

### Security & Realtime API
* `POST /api/purge` - Trigger emergency **Stinger Panic Purge** (overwrites CAS storage & clears RAM keys).
* `GET /sse` - Server-Sent Events stream endpoint for real-time dashboard updates.
* `POST /login` - Authentication endpoint.

---

## Quick Start & Local Setup

### Prerequisites
* **Go 1.21+** (Go 1.26 recommended)
* **GCC / Musl-dev** (Required for CGO with `go-sqlite3`)
* **Templ CLI**: `go install github.com/a-h/templ/cmd/templ@latest`

### 1. Build and Run via Makefile

```bash
# Clone the repository
git clone https://github.com/opeteer/hornetzDrive.git
cd hornetzDrive

# Generate Templ HTML components
make generate

# Build the standalone binary executable
make build

# Launch Hornetz Drive server
make run
```

By default, Hornetz Drive starts listening on `http://localhost:8071`.

### 2. Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8071` | HTTP server listening port |
| `DB_DRIVER` | `sqlite3` | Database driver (`sqlite3` or `postgres`) |
| `DB_DSN` | `file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL` | Database connection string |

---

## Container Deployment (Docker & Docker Compose)

Hornetz Drive includes a production-ready multi-stage `Dockerfile` and `docker-compose.yml` configured for PostgreSQL and Redis integration.

### Run with Docker Compose

```bash
docker-compose up -d --build
```

This starts:
1. **Hornetz Web Engine** listening on port `8071`
2. **PostgreSQL 15 Container** listening on port `5471`
3. **Redis 7 Container** listening on port `6371`

---

## Development Workflow

### Live Reloading & Component Generation
During development, regenerate Templ templates whenever `.templ` files are modified:

```bash
templ generate --watch
```

### Running Tests
Execute unit and benchmark tests for CAS storage, encryption, and repositories:

```bash
go test -v ./...
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
