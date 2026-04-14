FROM rust:1.88-bullseye

# RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*

# Install emsdk and emscripten
ADD https://github.com/emscripten-core/emsdk.git /emsdk
WORKDIR /emsdk
RUN ./emsdk install latest && \
    ./emsdk activate latest

WORKDIR /usr/game/rust/
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install just && \
    rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    rustup target add wasm32-unknown-emscripten --toolchain nightly

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    set -eux; \
    cd /emsdk && . /emsdk/emsdk_env.sh && cd /usr/game/rust && just threads;