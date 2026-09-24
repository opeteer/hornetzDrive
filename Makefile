.PHONY: all generate build run

all: generate build

generate:
	@echo "Generating Templ components..."
	~/go/bin/templ generate

build:
	@echo "Building Hornetz Drive single-binary executable..."
	# CGO is required for go-sqlite3. Static linking is preferred.
	CGO_ENABLED=1 go build -tags "sqlite_omit_load_extension" -ldflags "-s -w" -o bin/hornetz ./cmd/hornetz

run: build
	./bin/hornetz
