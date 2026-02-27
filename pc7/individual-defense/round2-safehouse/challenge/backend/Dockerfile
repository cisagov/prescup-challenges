FROM python:3.11-slim

WORKDIR /app

# Install system tools needed for Token 3 (zipcloak)
RUN apt-get update && \
    apt-get install -y --no-install-recommends zip unzip && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]

