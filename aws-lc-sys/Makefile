# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

include ../Makefile

test:
	cargo test --all-targets
	cargo test --release --all-targets

clippy-fix:
	cargo +nightly clippy --all-targets --features bindgen --fix --allow-dirty -- -W clippy::all  -W clippy::pedantic

ci: format clippy test api-diff-main

# Test builder functions using the builder-test crate
# This compiles builder/main.rs as a library and runs its #[cfg(test)] module
test-builder:
	cargo test -p builder-test

.PHONY: test ci clippy-fix test-builder
