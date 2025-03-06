# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

FROM ubuntu:24.04

ARG CMAKE_VERSION
ARG CMAKE_DOWNLOAD_URL
ARG CMAKE_SHA256

VOLUME ["/awslc"]

RUN apt-get update && \
    apt-get install -y ca-certificates build-essential cmake git wget curl jq unzip clang sudo golang zlib1g-dev libcurl4-openssl-dev libarchive-dev liblzma-dev xz-utils && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

RUN mkdir /cmake

COPY cmake_build.sh /
COPY aws_lc_rs_build.sh /
COPY entry.sh /

WORKDIR /cmake

RUN curl -L -o source.tar.gz "${CMAKE_DOWNLOAD_URL}"  && \
    echo "${CMAKE_SHA256} source.tar.gz" | sha256sum -c - && \
    mkdir source && \
    tar -x -f source.tar.gz -v --strip-components=1 -C source

WORKDIR /cmake/source

RUN /cmake_build.sh

RUN useradd -m docker
USER docker
RUN cd "${HOME}" && \
    git config --global --add safe.directory '*' && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rustup.sh && \
    chmod +x ./rustup.sh && \
    ./rustup.sh -y && \
    . "${HOME}/.cargo/env" && \
    cargo install --locked bindgen-cli && \
    rustup component add rustfmt clippy && \
    rm ./rustup.sh

ENV AWS_LC_SYS_CMAKE_BUILDER=1

ENTRYPOINT ["/entry.sh"]
