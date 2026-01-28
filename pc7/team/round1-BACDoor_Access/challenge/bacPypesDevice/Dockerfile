FROM python:3.13.4-slim

# Set working directory
WORKDIR /app

# Install BACpypes
RUN pip install bacpypes pyasyncore pyyaml requests
RUN apt-get update && apt-get install -y curl iputils-ping
RUN apt-get install tcpdump iproute2 -y

# Copy your BACnet simulation script
COPY ./app/ /app

# Run the simulator
CMD ["python", "light_sim.py"]
