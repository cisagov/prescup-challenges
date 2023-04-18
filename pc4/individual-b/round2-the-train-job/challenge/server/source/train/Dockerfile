FROM python:3.10-alpine

RUN apk update && apk add --no-cache docker-cli

COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
RUN pip install uvicorn --no-cache-dir

WORKDIR /app

COPY app.py .
COPY trainnetwork.py .
COPY network.json .

CMD ["python", "-m", "uvicorn", "--host", "0.0.0.0", "--port", "8001", "app:app"]
