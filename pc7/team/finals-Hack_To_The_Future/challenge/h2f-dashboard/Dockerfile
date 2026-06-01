FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /opt/dashboard

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /opt/dashboard/requirements.txt
RUN pip install --no-cache-dir -r /opt/dashboard/requirements.txt

COPY app /opt/dashboard/app
COPY content /opt/dashboard/content

# Copy static assets (css, js, fonts, images)
COPY app/static/ /opt/dashboard/app/static/

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()" || exit 1

CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "8", "-b", "0.0.0.0:8080", "app.app:app"]