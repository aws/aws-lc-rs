init:
	rustup component add rustfmt &&  git config core.hooksPath .githooks

format:
	cargo +nightly fmt -- --color auto --files-with-diff --verbose

clippy:
	cargo clippy -- -W clippy::all

asan:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --test ecdsa_tests              --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'`  --features asan

asan-release:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --release --test basic_rsa_test              --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --release --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'`  --features asan

coverage:
	cargo llvm-cov --open --hide-instantiations

ci:
	cargo fmt --check --verbose
	cargo test --release
	cargo test --no-default-features
	cargo test --no-default-features --features ring-io
	cargo test --no-default-features --features alloc
	cargo test --no-default-features --features threadlocal
