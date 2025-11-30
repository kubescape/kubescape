# Building Kubescape

This guide covers how to build Kubescape from source.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building the CLI](#building-the-cli)
- [Building Docker Images](#building-docker-images)
- [Build Options](#build-options)
- [Development Setup](#development-setup)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required

- **Go 1.23+** - [Installation Guide](https://golang.org/doc/install)
- **Git** - For cloning the repository
- **Make** - For running build commands

### Optional (for Docker builds)

- **Docker** - [Installation Guide](https://docs.docker.com/get-docker/)
- **Docker Buildx** - For multi-platform builds (included with Docker Desktop)

### Verify Prerequisites

```bash
go version    # Should be 1.21 or higher
git --version
make --version
docker --version  # Optional
```

---

## Building the CLI

### Clone the Repository

```bash
git clone https://github.com/kubescape/kubescape.git
cd kubescape
```

### Build with Make

```bash
# Build for your current platform
make build

# The binary will be at ./kubescape
./kubescape version
```

### Build Directly with Go

```bash
go build -o kubescape .
```

### Cross-Compilation

Build for different platforms:

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o kubescape-linux-amd64 .

# Linux (arm64)
GOOS=linux GOARCH=arm64 go build -o kubescape-linux-arm64 .

# macOS (amd64)
GOOS=darwin GOARCH=amd64 go build -o kubescape-darwin-amd64 .

# macOS (arm64 / Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o kubescape-darwin-arm64 .

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o kubescape-windows-amd64.exe .
```

---

## Building Docker Images

### Build All Images

```bash
make all
```

### Build CLI Docker Image

Build a Docker image containing only the Kubescape CLI:

```bash
# First build the binary
make build

# Then build the Docker image
docker buildx build \
  -t kubescape-cli:latest \
  -f build/kubescape-cli.Dockerfile \
  --build-arg="ks_binary=kubescape" \
  --load .
```

### Build Full Kubescape Image

Build the complete Kubescape image (includes HTTP handler):

```bash
docker buildx build \
  -t kubescape:latest \
  -f build/Dockerfile \
  --load .
```

### Multi-Platform Build

Build for multiple architectures:

```bash
docker buildx build \
  -t kubescape:latest \
  -f build/Dockerfile \
  --platform linux/amd64,linux/arm64 \
  --push .
```

---

## Build Options

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build the Kubescape binary |
| `make test` | Run unit tests |
| `make all` | Build everything |
| `make clean` | Remove build artifacts |

### Build Tags

You can use Go build tags to customize the build:

```bash
# Example with build tags
go build -tags "netgo" -o kubescape .
```

### Version Information

To embed version information in the build:

```bash
VERSION=$(git describe --tags --always)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT=$(git rev-parse HEAD)

go build -ldflags "-X main.version=$VERSION -X main.buildDate=$BUILD_DATE -X main.commit=$COMMIT" -o kubescape .
```

---

## Development Setup

### Install Development Dependencies

```bash
# Install golangci-lint for linting
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install other tools as needed
go mod download
```

### Run Tests

```bash
# Run all tests
make test

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./core/...
```

### Run Linter

```bash
golangci-lint run
```

### Code Formatting

```bash
go fmt ./...
```

---

## Troubleshooting

### Build Fails with "module not found"

```bash
# Update dependencies
go mod tidy
go mod download
```

### CGO-related Errors

If you encounter CGO errors, try building with CGO disabled:

```bash
CGO_ENABLED=0 go build -o kubescape .
```

### Docker Build Fails

Ensure Docker daemon is running and you have sufficient permissions:

```bash
# Check Docker status
docker info

# Run with sudo if needed (Linux)
sudo docker buildx build ...
```

### Out of Memory During Build

For systems with limited memory:

```bash
# Limit Go's memory usage
GOGC=50 go build -o kubescape .
```

---

## Dockerfiles

| File | Description |
|------|-------------|
| `build/Dockerfile` | Full Kubescape image with HTTP handler |
| `build/kubescape-cli.Dockerfile` | Minimal CLI-only image |

---

## Related Documentation

- [Contributing Guide](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md)
- [Architecture](../docs/architecture.md)
- [Getting Started](../docs/getting-started.md)
