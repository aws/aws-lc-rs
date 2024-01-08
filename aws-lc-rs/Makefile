include ../Makefile

UNAME_S := $(shell uname -s)

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
	cargo llvm-cov --no-fail-fast --fail-under-lines 95 --ignore-filename-regex "aws-lc-sys/*" --lcov --output-path lcov.info

test:
	cargo test --all-targets --features ring-benchmarks
	cargo test --release --all-targets
	cargo test --release --all-targets --features bindgen
ifeq ($(UNAME_S),Linux)
	cargo test --release --all-targets --features fips
	cargo test --no-default-features --features fips
endif
	cargo test --no-default-features --features aws-lc-sys
	cargo test --no-default-features --features aws-lc-sys,ring-sig-verify
	cargo test --no-default-features --features aws-lc-sys,ring-io
	cargo test --no-default-features --features aws-lc-sys,alloc

msrv:
	cargo msrv verify

ci: format clippy msrv test coverage api-diff-pub

.PHONY: asan asan-fips asan-release ci clippy coverage test msrv
