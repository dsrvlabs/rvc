.PHONY: build build-release check fmt clippy test coverage clean \
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

# Test
test:
	cargo test --workspace

test-verbose:
	cargo test -- --nocapture

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
