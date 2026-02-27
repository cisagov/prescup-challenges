FROM python:3.13.4-slim

# --- Dependencies ---
RUN pip install flask gunicorn sqlalchemy mysql-connector-python flask-login flask-wtf pillow qrcode[pil]
RUN apt update && apt install -y rsync ssh wait-for-it sudo

# --- Create non-root user ---
RUN useradd -m -s /bin/bash pawnuser

# --- SSH private key (for connecting TO pawn container) ---
RUN mkdir -p /home/pawnuser/.ssh
COPY warehouse_id_rsa /home/pawnuser/.ssh/id_rsa
RUN chmod 600 /home/pawnuser/.ssh/id_rsa && \
    chown -R pawnuser:pawnuser /home/pawnuser/.ssh

# --- Entrypoint ---
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# --- App setup ---
COPY app/ /app
RUN chown -R pawnuser:pawnuser /app
WORKDIR /app

# --- Drop to non-root ---
USER pawnuser

ENTRYPOINT [ "/entrypoint.sh" ]
# CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app", "--log-level=info", "--access-logfile=-", "--error-logfile=-"]
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--worker-class", "gthread", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
