# Ztatic Full-Stack Go Framework

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Security](https://img.shields.io/badge/Security-First-red?style=flat-square&logo=shield)](https://github.com/opeteer/ztatic-go-framework)
[![Architecture](https://img.shields.io/badge/Architecture-HOTW-success?style=flat-square)](https://github.com/opeteer/ztatic-go-framework)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

**Ztatic** is an enterprise-grade, security-first full-stack framework built on top of **Echo v5**. It transforms Go into a high-productivity full-stack monolith ecosystem using the **HOTW (HTML Over The Wire)** stack: **Templ**, **Hotwire (Turbo)**, **Alpine.js**, **esbuild**, and **Server-Sent Events (SSE)**.

With Ztatic, you write pure Go and HTML—**zero Node.js or npm required**—and compile your entire application (templates, JavaScript, CSS, migrations) into a **single, statically-linked binary** capable of pushing real-time updates in microsecond scale.

---

## Key Features & Architecture Pillars

### 1. Security Suite
* **Web Security Engine:** Built-in Web Application Firewall (WAF) payload inspection, nonces-based Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and Double Submit Cookie CSRF protection.
* **Data Privacy & Encryption:** AES-256-GCM field-level struct tag encryption (`ztatic:"encrypt"`), Argon2id password hashing, and zero-allocation PII masking for `slog`.

### 2. HOTW Frontend (Templ + Hotwire + Alpine.js)
* **Templ Integration:** Direct streaming of type-safe Go HTML templates into response buffers (`fullstack.Render`).
* **Smart Layout Unwrapping:** Automatically detects `Turbo-Frame` request headers and unwraps the outer application layout shell, cutting payload sizes by up to 80%.
* **Hotwire Turbo Streams:** Native support for Turbo 8 DOM mutation actions (`append`, `prepend`, `replace`, `update`, `remove`, `before`, `after`).
* **Alpine.js Morphing:** Automatic state-preserving morph headers (`X-Alpine-Morph`) for reactive client-side micro-interactions.

### 3. Native Asset Pipeline
* **Zero Node.js Dependency:** Native Go binding to the `esbuild` API compiles TypeScript, JavaScript, and CSS in sub-10ms.
* **Dual-Mode Asset Manager:** Disk-backed live reloads with timestamp cache-busting during development; Go `embed.FS` with immutable 1-year caching in production.
* **Content Hashing Manifest:** Automatic SHA-256 content hashing (`app.a8f9b2.js`) and manifest loading (`fullstack.AssetURL()`).

### 4. Realtime Engine (SSE & Pub/Sub Broker)
* **Topic-Based Event Broker:** High-throughput `MemoryBroker` leveraging thread-safe `sync.RWMutex` channels.
* **Zero-JS Realtime Streams:** Serves Turbo Streams directly over HTTP/1.1 Server-Sent Events (`<turbo-stream-from src="/sse?topic=room:101">`).
* **Proxy-Optimized:** Includes `X-Accel-Buffering: no` headers to bypass Nginx buffering bottlenecks.

### 5. Enterprise Data Tier
* **Panic-Safe Transactions:** `DBEngine.Transaction(ctx, fn)` automatically handles `COMMIT` on success, and `ROLLBACK` on explicit errors or runtime panics.
* **Generic Base Repository:** Go 1.18+ Generics-powered `BaseRepository[T]` eliminates boilerplate CRUD code without sacrificing type safety.
* **Embedded Migrations:** Embeds Goose SQL schema migrations directly inside your binary using `embed.FS`.

### 6. Unified Developer CLI (`ztatic`)
* **Scaffolding:** `ztatic new <project_name>` generates production-ready directory layouts.
* **Live Reload:** `ztatic dev` monitors `.go`, `.templ`, `.css`, and `.js` files, auto-compiling assets and restarting the process.
* **Single-Binary Build:** `ztatic build` creates an optimized, self-contained binary artifact ready for distribution.

---

## Quick Start

### Installation & Prerequisites
Ensure you have **Go 1.21+** installed.

```bash
# Clone the repository
git clone https://github.com/opeteer/ztatic-go-framework.git
cd ztatic-go-framework

# Build the ztatic CLI tool
go build -o ztatic ./cmd/ztatic
```

### 1. Scaffold a New Project
```bash
./ztatic new myapp
cd myapp
```

This creates the standard Ztatic project architecture:
```text
myapp/
├── assets/
│   ├── css/
│   └── js/
├── cmd/
│   └── server/
│       └── main.go
├── db/
│   └── migrations/
├── internal/
│   ├── controllers/
│   ├── models/
│   ├── repositories/
│   └── views/
│       ├── components/
│       └── layouts/
└── go.mod
```

### 2. Basic Server Example (`cmd/server/main.go`)
```go
package main

import (
	"log"
	
	"ztatic-go-framework"
	"ztatic-go-framework/fullstack"
)

func main() {
	// Initialize security-hardened engine
	app := ztatic.NewSecure()

	// Serve static assets
	fullstack.MountAssets(app.Engine, "assets", true)

	// Define routes
	app.GET("/", func(c ztatic.Context) error {
		return c.String(200, "Welcome to Ztatic Full-Stack Framework!")
	})

	log.Fatal(app.Start(":8080"))
}
```

---

## Module Usage Guide

### Rendering Templ Components & Turbo Streams

```go
package controllers

import (
	"github.com/labstack/echo/v5"
	"ztatic-go-framework/fullstack"
)

// Standard HTML View with smart layout unwrapping
func HandleHome(c *echo.Context) error {
	// If the request comes from a Turbo-Frame, AppLayout is bypassed automatically!
	return fullstack.RenderLayout(c, 200, views.AppLayout, views.HomePage())
}

// Turbo Stream DOM Mutation Response
func HandleUpdateMessage(c *echo.Context) error {
	// Appends a component into #messages container
	return fullstack.RenderTurboStream(
		c, 
		fullstack.StreamAppend, 
		"messages", 
		components.MessageCard("New Message"),
	)
}
```

### Real-Time Server-Sent Events (SSE)

```go
package main

import (
	"github.com/labstack/echo/v5"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/realtime"
)

func SetupRealtime(e *echo.Echo) {
	broker := realtime.NewMemoryBroker()

	// 1. Mount SSE stream endpoint
	e.GET("/sse", realtime.SSEHandler(broker))

	// 2. Broadcast DOM mutations from anywhere in your backend
	e.POST("/chat/send", func(c *echo.Context) error {
		broker.Publish(c.Request().Context(), "chat-room-1", fullstack.TurboStreamItem{
			Action:    fullstack.StreamAppend,
			Target:    "chat-box",
			Component: components.ChatMessage("Hello from Go!"),
		})
		return c.NoContent(200)
	})
}
```

In your HTML template, simply declare:
```html
<turbo-stream-from src="/sse?topic=chat-room-1"></turbo-stream-from>
<div id="chat-box"></div>
```

### Database Transactions & Generic Repositories

```go
package repositories

import (
	"context"
	"ztatic-go-framework/data"
)

type User struct {
	ID    int
	Email string
}

type UserRepository struct {
	*data.BaseRepository[User]
}

func NewUserRepository(db *data.DBEngine) *UserRepository {
	return &UserRepository{
		BaseRepository: data.NewBaseRepository[User](db, "users"),
	}
}

// Usage in Handler:
func CreateUserSafely(db *data.DBEngine, user *User) error {
	return db.Transaction(context.Background(), func(tx *sql.Tx) error {
		// All operations inside this closure rollback automatically on error or panic!
		_, err := tx.Exec("INSERT INTO users (email) VALUES (?)", user.Email)
		return err
	})
}
```

---

## Development & Production Workflow

### Development Mode (Live Reload)
```bash
./ztatic dev
```
Monitors template files (`.templ`), Go source files (`.go`), and assets (`.css`/`.js`), automatically generating components, bundling via `esbuild`, and restarting the server process seamlessly.

### Production Build
```bash
./ztatic build
```
Executes the production build pipeline:
1. `templ generate` compiles components to Go bytecode.
2. `esbuild` bundles and minifies JS/CSS assets targeting ES2022.
3. Content-hash manifest (`manifest.json`) is generated.
4. `go build -ldflags="-s -w" -trimpath` creates a zero-dependency static binary.

Deploy the resulting `bin/server` binary anywhere—no extra assets or runtime dependencies required!

---

## Performance Benchmarks

Benchmark results executed on AMD64 Linux (12th Gen Intel i5-12450H):

| Subsystem | Operation | Latency | Memory Overhead |
| :--- | :--- | :--- | :--- |
| **Asset Pipeline** | Manifest Hash Lookup (`AssetURL`) | **356.3 ns/op** | 64 B/op (3 allocs) |
| **Realtime Engine** | SSE Broadcast (100 Subscribers) | **4.6 µs/op** | ~46 ns / subscriber |
| **Data Engine** | Generic CRUD Identification | **0.005 ms** | Zero Heap Leaks |

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
