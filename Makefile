.PHONY: check

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --offline --all-targets -- -D warnings
	cargo test --workspace --offline
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --offline --no-deps
	node scripts/check-source.mjs
