FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev make \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask==3.0.3

# Source
COPY app.py /app/app.py
COPY abuse.py /app/abuse.py
COPY templates /app/templates
COPY static /app/static
COPY c /app/c
COPY keys /app/keys

# Build the firmware library (shared object) shipped to challengers
RUN mkdir -p /app/firmware \
    && gcc -shared -fPIC -O2 -fno-stack-protector -o /app/firmware/libboot.so /app/c/libboot.c

EXPOSE 8080
EXPOSE 2323
CMD ["python", "/app/app.py"]
