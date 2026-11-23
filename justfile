# List the available development commands.
default:
    @just --list

# Run the Rust CI checks (requires rustup target add thumbv7em-none-eabihf).
check: fmt-check check-core test test-all lint api-docs

# Format Rust sources.
fmt:
    cargo fmt --all

# Check Rust formatting.
fmt-check:
    cargo fmt --all -- --check

# Check the portable core on a bare-metal target.
check-core:
    cargo check --locked --target thumbv7em-none-eabihf --no-default-features

# Run the default-feature tests.
test:
    cargo test --locked

# Run the tests with all Cargo features enabled.
test-all:
    cargo test --locked --all-features

# Run Clippy across all targets and features.
lint:
    cargo clippy --locked --all-targets --all-features -- -D warnings

# Build the Rust API reference.
api-docs:
    cargo doc --locked --no-deps --all-features

# Preview the documentation with live reload.
site:
    zola --root site serve

# Validate the site and its internal links.
site-check:
    zola --root site check --skip-external-links

# Build the documentation in site/public/.
site-build:
    zola --root site build

# Run the native interoperability suite against the pinned Go peers.
interop:
    python3 -B tests/interop/run.py
