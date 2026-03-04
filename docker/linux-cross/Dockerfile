ARG CROSS_BASE_IMAGE=ubuntu:20.04
FROM $CROSS_BASE_IMAGE

ARG DEBIAN_FRONTEND=noninteractive
ARG GO_VERSION=1.23.8

RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends build-essential cmake clang ca-certificates curl && \
    ARCH=$(dpkg --print-architecture) && \
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz && \
    git config --global --add safe.directory '*' && \
    rm -rf /tmp/*

ENV PATH="/usr/local/go/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable && \
    . $HOME/.cargo/env && \
    cargo install --force --locked bindgen-cli && \
    mv $HOME/.cargo/bin/bindgen /usr/bin && \
    rm -rf $HOME/.cargo

ENV GOCACHE=/tmp