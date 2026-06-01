FROM python:3.12-slim

# Install system deps (optional, but nice to have)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLAG="flag{R3Z9_super_hard_web}"

EXPOSE 5000

CMD ["python", "app.py"]
