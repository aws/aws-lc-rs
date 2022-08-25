init:
	rustup component add rustfmt &&  git config core.hooksPath .githooks

format:
	cargo fmt -- --color auto --files-with-diff --verbose 

clippy:
	cargo clippy -- -W clippy::all

