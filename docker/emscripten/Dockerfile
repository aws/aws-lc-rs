ARG CROSS_BASE_IMAGE=ghcr.io/cross-rs/wasm32-unknown-emscripten:main
FROM $CROSS_BASE_IMAGE

ARG DEBIAN_FRONTEND=noninteractive
ARG GO_VERSION=1.23.8
ARG EMSDK_VERSION=3.1.74
ARG NODE_VERSION=20.18.0

# Install system dependencies and Go
RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends \
        build-essential cmake clang ca-certificates curl git python3 xz-utils && \
    ARCH=$(dpkg --print-architecture) && \
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz && \
    git config --global --add safe.directory '*' && \
    rm -rf /var/lib/apt/lists/* /tmp/*

# Install Node.js 20 LTS
# The cross-rs base image bundles an older Node.js that doesn't support the
# WebAssembly Exception Handling proposal, which modern Rust compilers generate
# for the wasm32-unknown-emscripten target.
RUN ARCH=$(uname -m | sed 's/x86_64/x64/' | sed 's/aarch64/arm64/') && \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${ARCH}.tar.xz" | \
    tar -xJ -C /usr/local --strip-components=1

# Install a fresh Emscripten SDK (the base image's /emsdk is not a git repo)
RUN rm -rf /emsdk && \
    git clone https://github.com/emscripten-core/emsdk.git /emsdk && \
    cd /emsdk && \
    ./emsdk install ${EMSDK_VERSION} && \
    ./emsdk activate ${EMSDK_VERSION} && \
    chmod -R a+rwX /emsdk

# Ensure the newly installed Node.js is used by Emscripten and the test runner
# rather than the older version bundled with the SDK
ENV EMSDK_NODE=/usr/local/bin/node
ENV PATH="/usr/local/bin:/usr/local/go/bin:${PATH}"

# Install bindgen-cli
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable && \
    . $HOME/.cargo/env && \
    cargo install --force --locked bindgen-cli && \
    mv $HOME/.cargo/bin/bindgen /usr/bin && \
    rm -rf $HOME/.cargo

ENV GOCACHE=/tmp