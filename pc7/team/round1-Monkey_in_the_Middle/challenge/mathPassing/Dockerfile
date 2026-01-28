FROM python:3.13.4-slim

# Install necessary networking tools
RUN apt-get update && apt-get install -y iproute2 iputils-ping net-tools

RUN apt install -y tcpdump

# Set up working directory
WORKDIR /app

COPY ./app.py /app/

CMD [ "python", "/app/app.py" ]