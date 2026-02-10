# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]
VOLUME ["/aws_lc_rs"]

WORKDIR /

ENV DEBIAN_FRONTEND=noninteractive

# Install base dependencies
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        file \
        gawk \
        gettext \
        git \
        libncurses-dev \
        libssl-dev \
        python3 \
        python3-distutils \
        rsync \
        sudo \
        unzip \
        wget \
        xz-utils \
        zlib1g-dev \
        zstd && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

# Download and extract OpenWrt SDK for aarch64
# Using 24.10 release for stability
ENV OPENWRT_SDK_URL="https://downloads.openwrt.org/releases/24.10.0/targets/mediatek/filogic/openwrt-sdk-24.10.0-mediatek-filogic_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
ENV OPENWRT_SDK_DIR="/openwrt-sdk"

RUN mkdir -p ${OPENWRT_SDK_DIR} && \
    wget --progress=dot:giga -O /tmp/openwrt-sdk.tar.zst "${OPENWRT_SDK_URL}" && \
    zstd -d /tmp/openwrt-sdk.tar.zst -o /tmp/openwrt-sdk.tar && \
    tar -xf /tmp/openwrt-sdk.tar -C ${OPENWRT_SDK_DIR} --strip-components=1 && \
    rm /tmp/openwrt-sdk.tar.zst /tmp/openwrt-sdk.tar

# Create non-root user for building
RUN useradd -m -s /bin/bash builder && \
    echo "builder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy scripts while still root and make them executable
COPY entry.sh /
COPY aws_lc_rs_build.sh /
RUN chmod +x /entry.sh /aws_lc_rs_build.sh

USER builder
WORKDIR /home/builder

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rustup.sh && \
    chmod +x ./rustup.sh && \
    ./rustup.sh -y && \
    . "${HOME}/.cargo/env" && \
    rustup target add aarch64-unknown-linux-musl && \
    rustup component add rustfmt clippy && \
    rm ./rustup.sh

# Configure git
RUN git config --global --add safe.directory '*'

ENTRYPOINT ["/entry.sh"]