FROM python:3.11-slim

RUN apt-get update && apt-get install -y sudo

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y nano iproute2 inetutils-ping curl host mtr-tiny tcpdump iptables sudo wget

COPY app.py .
COPY templates/ templates/
RUN useradd -ms /bin/bash ctf && echo 'ctf ALL=(root) NOPASSWD: /usr/local/bin/rootscript.sh' > /etc/sudoers.d/ctf && chmod 440 /etc/sudoers.d/ctf
COPY sudoers /usr/local/bin/rootscript.sh
RUN chmod +x /usr/local/bin/rootscript.sh

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 inetutils-ping curl host mtr-tiny tcpdump iptables

COPY app.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENV token1="TestToken1"

EXPOSE 80

CMD ["bash", "entrypoint.sh"]
#CMD ["python", "app.py"]
