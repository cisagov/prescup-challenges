## Dockerfile for building ABYSSNET
# Use a lightweight Ubuntu base
FROM ubuntu:20.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TOKEN4=${TOKEN4}

EXPOSE 9999

# Install dependencies: apache2, gcc, 32-bit libs
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       apache2 \
       gcc-multilib \
       python3 \
       make \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app
WORKDIR /app

COPY abyssnet_simulator.py ./

# RUN chmod +x /etc/systemd/system/abyssnet.service /etc/systemd/system/abyssnet.socket /app/abyssnet_simulator.py
RUN chmod +x /app/abyssnet_simulator.py

# Start AbyssNet again after service enabled
CMD ["python3", "abyssnet_simulator.py"]
