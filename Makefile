# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

init-submodules:
	git submodule update --init --recursive

deinit-submodules:
	git submodule deinit --all -f

init: init-submodules
	git config core.hooksPath .githooks
	rustup component add rustfmt clippy
	cargo install rust-script cargo-llvm-cov cargo-license public-api cargo-msrv --locked
	cargo install cargo-audit --features=fix --locked

update-aws-lc-fips-sys:
	git submodule update --init --remote --checkout -- aws-lc-fips-sys/aws-lc
	cd aws-lc-fips-sys/aws-lc && \
		git fetch --all && \
		git tag -l | xargs ../../scripts/tools/semver.rs fips-v2 | xargs git checkout

update-aws-lc-sys:
	git submodule update --init --remote --checkout -- aws-lc-sys/aws-lc
	cd aws-lc-sys/aws-lc && \
		git fetch --all && \
		git tag -l | xargs ../../scripts/tools/semver.rs main | xargs git checkout

update-submodules: update-aws-lc-fips-sys update-aws-lc-sys

lic:
	cargo +nightly license

audit:
	cargo +nightly audit fix --dry-run

format:
	cargo +nightly fmt -- --color auto --files-with-diff --verbose

api-diff-main:
	cargo public-api diff `git rev-parse main`..`git rev-parse HEAD`

api-diff-pub:
	cargo public-api diff latest

clippy:
	cargo +nightly clippy --all-targets --features bindgen -- -W clippy::all  -W clippy::pedantic

udep:
	cargo +nightly udeps --all-targets

.PHONY: init-aws-lc-sys init-aws-lc-fips-sys init-submodules init update-submodules lic audit format api-diff-main api-diff-pub clippy udep
