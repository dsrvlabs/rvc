.PHONY: build build-release check fmt clippy test test-fast coverage clean \
       docker-rvc docker-signer docker-keygen docker-all

# Build
build:
	cargo build

build-release:
	cargo build --release

# Docker
docker-rvc:
	docker build --target rvc -t rvc:latest .

docker-signer:
	docker build --target rvc-signer -t rvc-signer:latest .

docker-keygen:
	docker build --target rvc-keygen -t rvc-keygen:latest .

docker-all: docker-rvc docker-signer docker-keygen

# Check and lint
check:
	cargo check

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings

# Test
test:
	cargo test --workspace

test-verbose:
	cargo test -- --nocapture

# Fast tests via cargo-nextest (install once: cargo install cargo-nextest --locked).
# Falls back to plain cargo test if nextest is missing.
test-fast:
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace ; \
	else \
		echo "cargo-nextest not installed; falling back to cargo test --workspace" ; \
		echo "Install with: cargo install cargo-nextest --locked" ; \
		cargo test --workspace ; \
	fi

# Coverage
coverage:
	cargo llvm-cov --workspace

coverage-html:
	cargo llvm-cov --workspace --html

# Clean
clean:
	cargo clean

# All checks (CI)
ci: fmt-check clippy test
