include ../Makefile

test:
	cargo test --all-targets
	cargo test --release --all-targets

ci: format clippy test api-diff-main

.PHONY: test ci
