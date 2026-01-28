FROM rust:1.70-slim

RUN apt-get update -y && apt-get install -y --no-install-recommends \
      apache2 ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Rust project
COPY Cargo.toml build.rs ./
COPY src ./src
COPY static ./static

# Vendor crates at build time (when the builder has internet)
RUN cargo vendor /app/vendor \
 && mkdir -p /app/.cargo \
 && printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "/app/vendor"\n' > /app/.cargo/config.toml

# (Optional but helpful) warm the build cache once (tokens don't matter for deps)
# If your build.rs requires TOKENs even to compile, remove this block.
ENV TOKEN1=dummy TOKEN2=dummy TOKEN3=dummy TOKEN4=dummy TOKEN5=dummy
RUN cargo build --release --offline || true
ENV TOKEN1= TOKEN2= TOKEN3= TOKEN4= TOKEN5=

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]

