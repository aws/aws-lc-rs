# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

include ../Makefile

test:
	cargo test --all-targets
	cargo test --release --all-targets

clippy-fix:
	cargo +nightly clippy --all-targets --features bindgen --fix --allow-dirty -- -W clippy::all  -W clippy::pedantic

ci: format clippy test api-diff-main

.PHONY: test ci clippy-fix
