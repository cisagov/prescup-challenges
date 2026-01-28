FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

ENV TOKEN1=${TOKEN1} \
    TOKEN2=${TOKEN2} \
    TOKEN3=${TOKEN3} \
    TOKEN4=${TOKEN4} \
    TOKEN5=${TOKEN5}

RUN apt-get update && \
    apt-get install -y software-properties-common mtools dosfstools python3-pil && \
    add-apt-repository ppa:unit193/encryption -y && \
    apt-get install -y --no-install-recommends \
      mtools steghide zip unzip python3 apache2 dosfstools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /challenge
COPY scripts/build_deaddrop.py /challenge/build_deaddrop.py
COPY static/dead_drop.png /challenge/dead_drop.png

COPY static/index.html /var/www/html/index.html
COPY static/deaddrop-logo.svg /var/www/html/

EXPOSE 80

CMD ["python3", "/challenge/build_deaddrop.py"]
