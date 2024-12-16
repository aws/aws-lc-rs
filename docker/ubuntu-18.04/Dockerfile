# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

FROM --platform=linux/amd64 ubuntu:18.04

SHELL ["/bin/bash", "-c"]

ARG GOPROXY=direct

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get install -y cmake curl sudo  && \
    apt-get install -y --no-install-recommends gpg-agent software-properties-common && \
    add-apt-repository --yes ppa:longsleep/golang-backports && \
    add-apt-repository --yes --update ppa:ubuntu-toolchain-r/test && \
    apt-add-repository --yes ppa:git-core/ppa && \
    apt-get update && \
    apt-get install --assume-yes --no-install-recommends build-essential git cmake golang-go clang gcc-4.8 gcc-5 gcc-6 && \
    git config --global --add safe.directory '*' && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rustup.sh && \
    chmod +x ./rustup.sh && \
    ./rustup.sh -y && \
    . "$HOME/.cargo/env" && \
    rustup component add rustfmt clippy && \
    rm ./rustup.sh && \
    cargo install rust-script && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

ENV CC=gcc-6
ENV CXX=g++-6
