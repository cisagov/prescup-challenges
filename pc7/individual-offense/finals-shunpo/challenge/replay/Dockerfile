FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10003 --home /app --shell /usr/sbin/nologin replayuser

WORKDIR /app

COPY app /app
RUN pip install --no-cache-dir flask gunicorn

RUN chown -R replayuser:replayuser /app
USER replayuser

EXPOSE 7000

CMD ["gunicorn", "--workers", "1", "--threads", "2", "--bind", "0.0.0.0:7000", "replay:app"]
