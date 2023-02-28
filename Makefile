
init-submodules:
	git submodule update --init --recursive

init: init-submodules
	git config core.hooksPath .githooks
	rustup component add rustfmt clippy
	cargo install rust-script cargo-llvm-cov cargo-license public-api --locked
	cargo install cargo-audit --features=fix --locked

update-submodules:
	git submodule update --init --recursive --remote --checkout

lic:
	cargo +nightly license

audit:
	cargo +nightly audit fix --dry-run

format:
	cargo +nightly fmt -- --color auto --files-with-diff --verbose

api-diff-main:
	cargo public-api diff --deny changed --deny removed `git rev-parse main`..`git rev-parse HEAD`

api-diff-pub:
	cargo public-api diff --deny changed --deny removed latest

clippy:
	cargo +nightly clippy --all-targets -- -W clippy::all  -W clippy::pedantic

.PHONY: init-submodules init update-submodules lic audit format api-diff-main api-diff-pub clippy
