# Simple Makefile for the FleetCtrl client
# Wails v2.13.0 cannot generate bindings with Go 1.27.
# Export an exact toolchain so Wails subprocesses also use Go 1.26.
build build-client build-ui: export GOTOOLCHAIN := go1.26.0

# Optional version embedded into the service, e.g. `make build VERSION=2.4.1`.
VERSION ?=
LDFLAGS := $(if $(VERSION),-X KiskaLE/RustDesk-ID/internal/const.Version=$(VERSION))

build: build-client build-ui

# GOOS/GOARCH are set only for this command so the build also works on Linux and macOS.
# Exporting them for the whole target would also cross-compile the Wails CLI run below.
build-client:
	@echo "Building..."
	@mkdir -p bin
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/fleetctrl-client.exe ./cmd/main

build-ui:
	@mkdir -p bin
	@cd cmd/ui && go run github.com/wailsapp/wails/v2/cmd/wails@v2.13.0 build -clean -platform windows/amd64 -webview2 download -o fleetctrl-ui.exe
	@cp cmd/ui/build/bin/fleetctrl-ui.exe bin/fleetctrl-ui.exe


test:
	@echo "Running tests..."
	@go test ./...


test-v:
	@echo "Running tests (verbose)..."
	@go test -v ./...


test-cover:
	@echo "Running tests with coverage..."
	@go test ./... -coverprofile=coverage.out
	@go tool cover -func=coverage.out


test-apps:
	@echo "Running app tests..."
	@go test -v ./internal/apps/...


# Run the application
run:
	@go run cmd/main/main.go
