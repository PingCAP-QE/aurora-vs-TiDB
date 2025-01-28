# Compiler
GO ?= go

# Build settings
BUILD_DIR ?= ./bin
MAIN_SRC := ./cmd/main.go
MAIN_BIN ?= $(BUILD_DIR)/aurora-vs-TiDB
GOOS ?= linux
GOARCH ?= amd64

# Default target
all: build

# Build the main binary
build:
	@echo "Building main binary for GOARCH=$(GOARCH)..."
	@$(GO) build -o $(MAIN_BIN) $(MAIN_SRC)
	@chmod +x $(MAIN_BIN)
	@echo "Main binary built: $(MAIN_BIN)"

# Run the main binary
run: build
	@echo "Running main binary..."
	@$(MAIN_BIN)

# Clean up compiled files
clean:
	@echo "Cleaning up compiled files..."
	@rm -f $(MAIN_BIN)
	@echo "Cleaned up compiled files."

# Build for ARM (32-bit)
build-arm:
	@$(MAKE) GOARCH=arm GOOS=linux build

# Build for ARM64 (64-bit)
build-arm64:
	@$(MAKE) GOARCH=arm64 GOOS=linux build

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build the main binary"
	@echo "  build      - Build the main binary"
	@echo "  run        - Run the main binary"
	@echo "  clean      - Clean up compiled files"
	@echo "  build-arm  - Build for ARM architecture (32-bit)"
	@echo "  build-arm64 - Build for ARM architecture (64-bit)"
	@echo "  help       - Show this help message"

.PHONY: all build run clean build-arm build-arm64 help
