# Compiler and flags
CARGO = cargo

# Target binaries and output directory
HOST_BINARY = vhost
ROUTER_BINARY = vrouter
OUT_DIR = ./bin

# Source files
HOST_SRC = src/bin/vhost.rs
ROUTER_SRC = src/bin/vrouter.rs

# Default target
all: check-dependencies build

# Ensure all required crates are downloaded
check-dependencies:
	$(CARGO) fetch

# Build all binaries
build: $(OUT_DIR)/$(HOST_BINARY) $(OUT_DIR)/$(ROUTER_BINARY)

# Build and copy vhost binary
$(OUT_DIR)/$(HOST_BINARY): $(HOST_SRC)
	$(CARGO) build --release --bin vhost
	mkdir -p $(OUT_DIR)
	cp target/release/vhost $(OUT_DIR)/$(HOST_BINARY)

# Build and copy vrouter binary
$(OUT_DIR)/$(ROUTER_BINARY): $(ROUTER_SRC)
	$(CARGO) build --release --bin vrouter
	mkdir -p $(OUT_DIR)
	cp target/release/vrouter $(OUT_DIR)/$(ROUTER_BINARY)

# Clean up generated binaries and build artifacts
clean:
	rm -rf $(OUT_DIR)
	$(CARGO) clean

# Phony targets to ensure they are always run
.PHONY: all build clean check-dependencies