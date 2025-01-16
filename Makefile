# Makefile for building and managing the Go project

# Compiler
GO ?= go

# Build settings
BUILD_DIR ?= ./bin
MAIN_SRC ?= main.go aurora_perf.go
MAIN_BIN ?= $(BUILD_DIR)/aurora-vs-TiDB
GOOS=linux 
GOARCH=amd64

# All targets
all: build

# Build the main binary
build: $(MAIN_BIN)

# Build the main binary
$(MAIN_BIN): $(MAIN_SRC)
	@echo "Building main binary..."
	@$(GO) build -o $@ $(MAIN_SRC)
	@chmod +x $@ 
	@echo "Main binary built: $@"

# Run the main binary
run: $(MAIN_BIN)
	@echo "Running main binary..."
	@$(MAIN_BIN)

# Clean up compiled files
clean:
	@echo "Cleaning up compiled files..."
	@rm -f $(MAIN_BIN)
	@echo "Cleaned up compiled files."

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build the main binary"
	@echo "  build    - Build the main binary"
	@echo "  run      - Run the main binary"
	@echo "  clean    - Clean up compiled files"
	@echo "  help     - Show this help message"

.PHONY: all build run clean help