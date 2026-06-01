FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl bash jq openssl coreutils \
 && pip install fastapi uvicorn[standard] \
 && rm -rf /var/lib/apt/lists/*

USER root

# Create group/user first so files can be owned correctly
RUN groupadd -g 1000 appuser \
 && useradd -m -s /bin/bash -u 1001 -g appuser appuser

# Normalize entrypoint, place it on an exec-safe path
RUN set -eux


# Create structure
RUN mkdir -p /app/data/ /app/certs/
COPY app/ /app
COPY entrypoint.sh /app/
RUN chown -R appuser:appuser /app/data /app /app/certs


# Normalize line endings, perms, and ownership
RUN sed -i 's/\r$//' /app/entrypoint.sh \
 && chmod +x /app/entrypoint.sh 


USER appuser

EXPOSE 8080

# Let the shell read+run the script (works even if /app is noexec)
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]

