UNAME_S := $(shell uname -s)

init:
	rustup component add rustfmt clippy &&  git config core.hooksPath .githooks
	cargo install rust-script
	cargo install cargo-llvm-cov cargo-license
	cargo install cargo-audit --features=fix

lic:
	cargo +nightly license

audit:
	cargo +nightly audit fix --dry-run

format:
	cargo +nightly fmt -- --color auto --files-with-diff --verbose

# TODO: Make clippy more annoying
clippy:
	cargo +nightly clippy --all-targets -- -W clippy::all  -W clippy::pedantic # -W clippy::restriction -W clippy::nursery -D warnings

asan:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --test ecdsa_tests              --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'`  --features asan

asan-release:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --release --test basic_rsa_test           --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --release --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'`  --features asan

asan-fips:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --test ecdsa_tests          --target `rustc -vV | sed -n 's|host: ||p'` --no-default-features --features fips,asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'` --no-default-features --features fips,asan

coverage:
	cargo llvm-cov --open --hide-instantiations

ci:
	cargo fmt --check --verbose
	cargo test --all-targets --features ring-benchmarks
	cargo test --release --all-targets
ifeq ($(UNAME_S),Linux)
	cargo test --release --all-targets --features fips
	cargo test --no-default-features --features fips
endif
	cargo test --no-default-features --features aws-lc-sys
	cargo test --no-default-features --features aws-lc-sys,ring-sig-verify
	cargo test --no-default-features --features aws-lc-sys,ring-io
	cargo test --no-default-features --features aws-lc-sys,alloc
