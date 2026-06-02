FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10004 --home /app --shell /usr/sbin/nologin bridgeuser

WORKDIR /app
COPY bridge.py /app/bridge.py

RUN chown -R bridgeuser:bridgeuser /app
USER bridgeuser

EXPOSE 5683/udp

CMD ["python3", "-u", "bridge.py"]
