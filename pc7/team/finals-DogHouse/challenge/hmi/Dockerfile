FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends dos2unix \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.0 pymodbus==3.6.6

COPY app.py /app.py
RUN dos2unix /app.py

EXPOSE 8080
CMD ["python3", "/app.py"]
