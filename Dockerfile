# Stage 1: Build the statically linked Go binary
FROM golang:alpine AS builder

# Install build dependencies for CGO (SQLite requires gcc)
RUN apk add --no-cache gcc musl-dev make

WORKDIR /app

# Copy dependency graphs and local replaced modules
COPY go.mod go.sum ./
COPY echo/ ./echo/
RUN go mod download

# Copy source code
COPY . .

# Build the binary with CGO enabled (for sqlite3 support)
RUN CGO_ENABLED=1 GOOS=linux go build -tags "sqlite_omit_load_extension" -ldflags "-s -w" -o bin/hornetz ./cmd/hornetz

# Stage 2: Minimal Runtime Environment
FROM alpine:latest

# Install tzdata and ca-certificates for network and time
RUN apk add --no-cache tzdata ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/bin/hornetz .

# Create storage directories
RUN mkdir -p storage/cas storage/tmp && chmod -R 777 storage

# Expose the server port
EXPOSE 8071

# Default Environment Variables (SQLite mode)
ENV DB_DRIVER=sqlite3
ENV DB_DSN="file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL"
ENV PORT=8071

# Run the binary
ENTRYPOINT ["./hornetz"]
