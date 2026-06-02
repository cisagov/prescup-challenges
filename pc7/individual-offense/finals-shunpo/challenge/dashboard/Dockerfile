FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin spuser

WORKDIR /app

RUN mkdir -p /app/templates /app/static /app/bootstrap /data /tmp/shunpo-build \
 && chown -R spuser:spuser /app /data /tmp/shunpo-build

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY entrypoint.sh /app/entrypoint.sh
COPY bootstrap/ /app/bootstrap/
COPY templates/ /app/templates/
COPY static/ /app/static/

RUN chmod 0555 /app/entrypoint.sh /app/bootstrap/generate_data.py \
 && chown -R spuser:spuser /app

USER spuser

EXPOSE 3000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "--workers", "2", "--threads", "2", "--bind", "0.0.0.0:3000", "app:app"]
