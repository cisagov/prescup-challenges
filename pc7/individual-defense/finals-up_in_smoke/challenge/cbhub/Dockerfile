FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3

COPY app.py /app/app.py
COPY abuse.py /app/abuse.py
COPY audiogen.py /app/audiogen.py
COPY templates /app/templates
COPY static /app/static
COPY assets /app/assets

EXPOSE 8080
CMD ["python", "/app/app.py"]
