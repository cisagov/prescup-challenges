FROM python:3.14.0b2-bookworm

RUN pip install Flask

COPY flagserve.py /flagserve.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV token1=""
ENV token3=""
ENV token4=""

EXPOSE 80

CMD ["/entrypoint.sh"]