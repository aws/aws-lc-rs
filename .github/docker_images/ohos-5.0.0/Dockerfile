# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

FROM ubuntu:24.04

SHELL ["/bin/bash", "-c"]
VOLUME ["/aws_lc_rs"]

WORKDIR /

RUN apt-get update && \
    apt-get install -y ca-certificates build-essential cmake git wget curl jq unzip clang sudo && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

RUN mkdir /ohos && \
    wget --progress=dot:giga https://repo.huaweicloud.com/openharmony/os/5.0.0-Release/ohos-sdk-windows_linux-public.tar.gz && \
    wget https://repo.huaweicloud.com/openharmony/os/5.0.0-Release/ohos-sdk-windows_linux-public.tar.gz.sha256 && \
    diff <(sha256sum ohos-sdk-windows_linux-public.tar.gz | cut -d ' ' -f 1) ohos-sdk-windows_linux-public.tar.gz.sha256 && \
    tar zxvf ohos-sdk-windows_linux-public.tar.gz -C /ohos && \
    cd /ohos/linux && \
    unzip native-linux-x64-5.0.0.*-Release.zip && \
    rm -rf /ohos/windows /ohos/linux/*.zip

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
    rustup target add aarch64-unknown-linux-ohos armv7-unknown-linux-ohos x86_64-unknown-linux-ohos && \
    rm ./rustup.sh

COPY aws_lc_rs_build.sh /
COPY entry.sh /

ENV CMAKE_TOOLCHAIN_FILE=/ohos/linux/native/build/cmake/ohos.toolchain.cmake
ENV OHOS_NDK_HOME=/ohos/linux
ENV OHOS_SDK_NATIVE=/ohos/linux/native

ENTRYPOINT ["/entry.sh"]
