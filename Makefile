# Developer shortcuts. CI runs these checks too, plus more (see .github/workflows/ci.yml).
MUSL_TARGETS := x86_64-unknown-linux-musl aarch64-unknown-linux-musl

.PHONY: fmt lint test deny check build-musl clean

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --locked
	cargo test --workspace --locked --features testing

deny:
	@command -v cargo-deny >/dev/null 2>&1 || { echo "cargo-deny not found: cargo install cargo-deny --locked"; exit 1; }
	cargo deny check

check:
	cargo fmt --all --check
	$(MAKE) lint test deny

build-musl:
	for t in $(MUSL_TARGETS); do cargo build --release --locked --target $$t || exit 1; done

clean:
	cargo clean
