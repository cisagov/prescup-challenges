
FROM python:3.13.4-slim

RUN apt-get update && apt-get install -y iproute2 iputils-ping net-tools
RUN pip install flask PyYAML flask-pymongo flask-login python-dotenv
RUN apt-get install -y build-essential python3-dev libarchive-dev zlib1g-dev libbz2-dev liblzma-dev pkg-config sudo zip unzip
RUN pip install "python-libarchive==4.2.1" markdown beautifulsoup4 flask-wtf email-validator werkzeug

COPY app/ /app
RUN cp /app/game.yml /app/static/game_original.yml
WORKDIR /app/static/themes
RUN zip -r /app/static/game_theme_original.zip pccc
WORKDIR /

RUN groupadd -r user && useradd -r -g user -m -s /bin/bash user
RUN groupadd -r yaml && useradd -r -g yaml -M -s /usr/sbin/nologin -d /nonexistent yaml

# Allow user to sudo as yaml, no password
RUN echo 'user ALL=(yaml) NOPASSWD: ALL' > /etc/sudoers.d/user_as_yaml && chmod 0440 /etc/sudoers.d/user_as_yaml

RUN mkdir -p /app && chown -R user:user /app

# Lock everything down
RUN find /app -type f -exec chmod 0440 {} \; && \
    find /app -type d -exec chmod 0555 {} \;

# Selectively set write or other special permissions
RUN touch /app/game.json && chmod 0666 /app/game.yml /app/game.json
RUN touch /app/yamlLog.txt && chmod 0666 /app/yamlLog.txt
RUN touch /app/log.txt && chown -R user:user /app/log.txt && chmod 0600 /app/log.txt
RUN chmod 444 /app/handle_yaml.py

RUN chmod 440 /app/app.py

RUN chown -R user:user /app/static/themes && chmod -R u+rwX /app/static/themes
RUN touch /app/token.txt && chown -R user:user /app/token.txt && chmod 0644 /app/token.txt
RUN chown -R user:user /app/names.txt && chmod 0644 /app/names.txt

COPY entrypoint.sh /entrypoint.sh
RUN chown -R user:user /entrypoint.sh && chmod 0500 /entrypoint.sh
USER user
# CMD ["python", "/app/app.py"]
ENTRYPOINT [ "/entrypoint.sh" ]
