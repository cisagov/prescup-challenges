FROM python:3.13.4-slim

RUN pip install flask gunicorn sqlalchemy mysql-connector-python flask-login flask-wtf email-validator pillow
RUN apt update && apt install -y rsync openssh-server wait-for-it sudo

# Create non-root user
RUN useradd -m -s /bin/bash pawnuser

# Setup SSH for pawnuser
RUN mkdir -p /home/pawnuser/.ssh
COPY warehouse_id_rsa.pub /home/pawnuser/.ssh/authorized_keys
RUN chmod 700 /home/pawnuser/.ssh && \
    chmod 600 /home/pawnuser/.ssh/authorized_keys && \
    chown -R pawnuser:pawnuser /home/pawnuser/.ssh

# Configure SSH server
RUN mkdir -p /var/run/sshd
RUN sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
RUN echo "pawnuser ALL=(ALL) NOPASSWD: /usr/sbin/sshd" >> /etc/sudoers

# Entrypoint and app
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

COPY app/ /app
RUN mkdir /app/static/uploads
RUN chown -R pawnuser:pawnuser /app
WORKDIR /app

USER pawnuser

ENTRYPOINT [ "/entrypoint.sh" ]
# CMD ["gunicorn", "-b", "0.0.0.0:8080", "--log-level", "info", "--capture-output", "--error-logfile", "-", "--access-logfile", "-", "app:app"]
# CMD ["flask", "--app", "app.py", "run", "--host=0.0.0.0", "--port=8080"]
# CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--worker-class", "gthread", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
