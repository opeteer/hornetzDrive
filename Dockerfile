# Stage 1: Build React frontend
FROM node:20-bookworm-slim AS frontend-builder
WORKDIR /app/frontend
# Copy dependency files
COPY frontend/package*.json ./
RUN npm ci
# Copy source and build
COPY frontend/ .
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.21-bookworm AS backend-builder
WORKDIR /app/backend
# Copy dependency files
COPY backend/go.mod backend/go.sum ./
RUN go mod download
# Copy source files
COPY backend/ .
# Copy frontend dist to backend for //go:embed (overwriting local ones if any)
COPY --from=frontend-builder /app/frontend/dist ./frontend_dist
# Build with CGO enabled (required for go-sqlite3)
RUN CGO_ENABLED=1 GOOS=linux go build -o hornetz .

# Stage 3: Runner image
FROM debian:bookworm-slim
WORKDIR /app
# Install certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=backend-builder /app/backend/hornetz .

# Default Environment Variables
ENV STORAGE_DIR=/data/storage
ENV DB_PATH=/data/metadata.db
ENV PORT=:8061

EXPOSE 8061
VOLUME ["/data"]

CMD ["./hornetz"]
