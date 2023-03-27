# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

include ../Makefile

test:
	cargo test --all-targets
	cargo test --release --all-targets

ci: format clippy test api-diff-main

.PHONY: test ci
