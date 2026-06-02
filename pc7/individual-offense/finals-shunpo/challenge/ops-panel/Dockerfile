FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10002 --home /app --shell /usr/sbin/nologin opsuser

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY config.py /app/config.py
COPY wsgi.py /app/wsgi.py
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY entrypoint.sh /app/entrypoint.sh
COPY templates/ /app/templates/

RUN chmod 0555 /app/entrypoint.sh \
 && chown -R opsuser:opsuser /app

USER opsuser

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "-c", "/app/gunicorn.conf.py", "wsgi:app"]
