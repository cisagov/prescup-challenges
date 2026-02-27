FROM rust:1.78-slim AS replayd-builder
WORKDIR /build/replayd
COPY replayd/Cargo.toml replayd/Cargo.lock* ./
COPY replayd/src ./src
# Build two binaries: PIE (default) and non-PIE (optional / easier mode)
RUN cargo build --release && cp target/release/replayd /build/replayd/replayd_pie

# For "no PIE", rebuild with a linker flag. If it fails for any reason, fall back to the PIE build.
RUN (RUSTFLAGS="-C link-arg=-no-pie" cargo build --release && cp target/release/replayd /build/replayd/replayd_nopie) || cp /build/replayd/replayd_pie /build/replayd/replayd_nopie

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser \
  && apt-get update \
  && apt-get install -y --no-install-recommends tini ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=replayd-builder /build/replayd/replayd_pie /app/bin/replayd
# Optional no-PIE binary may not exist depending on toolchain; keep build resilient
COPY --from=replayd-builder /build/replayd/replayd_nopie /app/bin/replayd_nopie

RUN chmod +x /app/bin/replayd /app/bin/replayd_nopie || true

USER appuser
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--workers","1"]
