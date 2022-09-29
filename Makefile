init:
	rustup component add rustfmt &&  git config core.hooksPath .githooks

format:
	cargo fmt -- --color auto --files-with-diff --verbose

clippy:
	cargo clippy -- -W clippy::all

asan:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --test ecdsa_tests --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --all-targets --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
