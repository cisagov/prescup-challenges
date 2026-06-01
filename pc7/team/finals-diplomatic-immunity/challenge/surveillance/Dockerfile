FROM python:3.12-slim

USER root

# Create group/user first so files can be owned correctly
RUN groupadd -g 1000 appuser \
 && useradd -m -s /bin/bash -u 1001 -g appuser appuser

# Install just the utilities used in the Camellia/OCR pipeline
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl jq openssl bash ffmpeg tesseract-ocr unzip zip coreutils \
 && pip install --no-cache-dir fastapi uvicorn[standard] pillow \
 && rm -rf /var/lib/apt/lists/*

# Create structure
RUN mkdir -p /app/data/frames /app/data/artifacts
RUN chown -R appuser:appuser /app


# App files
WORKDIR /app
COPY app/ /app
COPY entrypoint.sh /app/

# Normalize line endings, perms, and ownership
RUN sed -i 's/\r$//' /app/entrypoint.sh \
 && chmod +x /app/entrypoint.sh 

# Drop root for runtime
USER appuser

EXPOSE 8080

# Let the shell read+run the script (works even if /app is noexec)
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]

# Optional: allow passing args via `docker run ... -- <args>` if you ever want.
# If you prefer, omit CMD entirely; ENTRYPOINT execs uvicorn.
# CMD []
