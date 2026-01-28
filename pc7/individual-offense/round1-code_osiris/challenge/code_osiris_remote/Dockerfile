## Dockerfile for building and hosting code_osiris_v1 on Apache2
# Use a lightweight Ubuntu base
FROM ubuntu:20.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TOKEN3=${TOKEN3}

EXPOSE 9999

RUN mkdir -p /app
WORKDIR /app

# Install dependencies: apache2, gcc, 32-bit libs
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       apache2 \
       sudo \
       python3 \
       gcc-multilib \
       make \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
COPY code_osiris_remote.py ./




# Start AbyssNet again after service enabled
CMD ["python3", "code_osiris_remote.py"]
