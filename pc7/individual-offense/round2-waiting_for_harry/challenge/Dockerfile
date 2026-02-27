FROM rust:1.93-bullseye AS gdsdecomp_builder
ENV DEBIAN_FRONTEND=noninteractive

# Install emsdk and emscripten
ADD https://github.com/emscripten-core/emsdk.git /emsdk
WORKDIR /emsdk
RUN ./emsdk install latest && \
    ./emsdk activate latest

# Add dotnet 9 sdk
RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb

# Add python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        powershell \
        python3 \
        cmake \
        ca-certificates \
        xz-utils \
        pkg-config \
        libatomic1 \
        dotnet-sdk-9.0 \
        build-essential \
        scons \
        libx11-dev \
        libxcursor-dev \
        libxinerama-dev \
        libgl1-mesa-dev \
        libglu1-mesa-dev \
        libasound2-dev \
        libpulse-dev \
        libudev-dev \
        libxi-dev \
        libxrandr-dev \
        libwayland-dev \
        zip && \
    rm -rf /var/lib/apt/lists/*

# Compile gdsdecomp for patching the game with the token at runtime
WORKDIR /godot
RUN cd /emsdk \
    && . /emsdk/emsdk_env.sh \
    && cd /godot \
    && git clone -b gdre-wb-e2a10cd4 --single-branch https://github.com/nikitalita/godot.git /godot \
    && git clone https://github.com/GDRETools/gdsdecomp.git /godot/modules/gdsdecomp \
    && cd /godot/modules/gdsdecomp \
    && git fetch && git checkout 8274139ff7a77cf012f3a63e9313ca05962b590e \
    && cd /godot \
    && scons platform=linuxbsd target=editor && rm -rf editor \
    && scons platform=linuxbsd target=template_debug \
    && scons platform=linuxbsd target=template_release \
    && chmod a+x /godot/bin/godot* \
    && cd /godot/modules/gdsdecomp/standalone \
    && pwsh -File /godot/modules/gdsdecomp/.scripts/export.ps1 "Linux/X11" -path ".export/gdre_tools.x86_64" -cmd /godot/bin/godot.linuxbsd.editor.x86_64 \
    && cd /godot/modules/gdsdecomp/standalone/.export/ \
    && zip gdre_tools_linux_x86_64.zip ./* \
    && mkdir -p /dist \
    && mv ./* /dist/ \
    && rm -rf /godot/*

FROM rust:1.93-bullseye AS game_builder
ENV DEBIAN_FRONTEND=noninteractive

# Install emsdk and emscripten
ADD https://github.com/emscripten-core/emsdk.git /emsdk
WORKDIR /emsdk
RUN ./emsdk install 4.0.15 && \
    ./emsdk activate 4.0.15

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    wget lsb-release \
    software-properties-common gnupg \
    gcc-multilib \
    && bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)" \
    && rm -rf /var/lib/apt/lists/* 

ARG GODOT_VERSION="4.5.1"
ARG RELEASE_NAME="stable"
ARG GODOT_PLATFORM="linux.x86_64"

ENV GODOT_ZIP="Godot_v${GODOT_VERSION}-${RELEASE_NAME}_${GODOT_PLATFORM}.zip"

RUN wget https://github.com/godotengine/godot-builds/releases/download/${GODOT_VERSION}-${RELEASE_NAME}/Godot_v${GODOT_VERSION}-${RELEASE_NAME}_${GODOT_PLATFORM}.zip \
    && wget https://github.com/godotengine/godot-builds/releases/download/${GODOT_VERSION}-${RELEASE_NAME}/Godot_v${GODOT_VERSION}-${RELEASE_NAME}_export_templates.tpz \
    && mkdir -p ~/.cache \
    && mkdir -p ~/.config/godot \
    && mkdir -p ~/.local/share/godot/export_templates/${GODOT_VERSION}.${RELEASE_NAME} \
    && unzip Godot_v${GODOT_VERSION}-${RELEASE_NAME}_${GODOT_PLATFORM}.zip \
    && mv Godot_v${GODOT_VERSION}-${RELEASE_NAME}_${GODOT_PLATFORM} /usr/local/bin/godot4 \
    && unzip Godot_v${GODOT_VERSION}-${RELEASE_NAME}_export_templates.tpz \
    && mv templates/* ~/.local/share/godot/export_templates/${GODOT_VERSION}.${RELEASE_NAME} \
    && rm -f Godot_v${GODOT_VERSION}-${RELEASE_NAME}_export_templates.tpz Godot_v${GODOT_VERSION}-${RELEASE_NAME}_${GODOT_PLATFORM}.zip


RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && rustup target add wasm32-unknown-emscripten --toolchain nightly \
    && cargo install just

WORKDIR /app/rust_build
COPY ./game_rust/rust .
# RUN rustc +nightly -Z unstable-options --target=wasm32-unknown-emscripten --print target-spec-json
# RUN rustc +nightly - --crate-name ___ --print=file-names --crate-type cdylib --print=sysroot --print=split-debuginfo --print=crate-name --print=cfg -Wwarnings < /dev/null
# RUN rustup override set nightly-2025-12-01
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/rust_build/target \
    cd /emsdk \
    && . /emsdk/emsdk_env.sh \
    && cd /app/rust_build \
    && just threads nothreads linux \
    && mkdir -p \
        /app/rust/target/x86_64-unknown-linux-gnu/debug \
        /app/rust/target/x86_64-unknown-linux-gnu/release \
        /app/rust/target/wasm32-unknown-emscripten/debug \
        /app/rust/target/wasm32-unknown-emscripten/release \
        dist/debug/threads \
        dist/release/threads \
        dist/debug/nothreads \
        dist/release/nothreads \
    && mv target/x86_64-unknown-linux-gnu/debug/librust.so /app/rust/target/x86_64-unknown-linux-gnu/debug/librust.so \
    && mv target/x86_64-unknown-linux-gnu/release/librust.so /app/rust/target/x86_64-unknown-linux-gnu/release/librust.so \
    && mv target/wasm32-unknown-emscripten/debug/rust.*.wasm /app/rust/target/wasm32-unknown-emscripten/debug/ \
    && mv target/wasm32-unknown-emscripten/release/rust.*.wasm /app/rust/target/wasm32-unknown-emscripten/release/ \
    && mv target/wasm32-unknown-emscripten/debug/rust.threads.wasm.map dist/debug/threads/rust.wasm.map \
    && mv target/wasm32-unknown-emscripten/debug/rust.nothreads.wasm.map dist/debug/nothreads/rust.wasm.map

COPY ./game_rust/godot /app/godot
WORKDIR /app/godot
RUN mkdir ../build && godot4 --headless --verbose --export-release Web && mv ../build ../release
RUN mv /app/godot/html/index.debug.html /app/godot/html/index.html
RUN mkdir ../build && godot4 --headless --verbose --export-debug Web && mv ../build ../debug
RUN mv /app/rust_build/dist/debug/threads /app/rust_build/dist/debug/nothreads /app/debug/

FROM rust:1.93-bullseye AS server_builder

# RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/server
COPY server/ .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/server/target \
    set -eux; \
    cargo build --release; \
    objcopy --compress-debug-sections target/release/server ./server

FROM debian:bullseye AS server

RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates && rm -rf /var/lib/apt/lists/*

# Add dotnet 9 sdk
RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb

# Add python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        xz-utils \
        libatomic1 \
        dotnet-sdk-9.0 \
        libfontconfig1-dev \
        libx11-dev \
        libxcursor-dev \
        libxinerama-dev \
        libgl1-mesa-dev \
        libglu1-mesa-dev \
        libasound2-dev \
        libpulse-dev \
        libudev-dev \
        libxi-dev \
        libxrandr-dev \
        libwayland-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=server_builder /usr/src/server/server server
COPY --from=gdsdecomp_builder /dist/* /gdsdecomp/
COPY --from=game_builder /app/release/ /app/game/
RUN mkdir -p /app/game/debug/
COPY --from=game_builder /app/debug/ /app/game/debug/
COPY server/templates/ /app/templates/
COPY server/static/ /app/static/
COPY server/Rocket.toml /app/Rocket.toml

COPY ./game_rust/godot/addons/anti-cheating/ac_node.gd /app/resources/

# Setup entrypoint
COPY server.sh /app/server.sh
RUN chmod +x /app/server.sh

ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=80

ENTRYPOINT [ "/app/server.sh" ]