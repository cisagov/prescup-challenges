FROM python:3.14.0b2-bookworm

RUN pip install Flask
RUN apt update && apt install -y dos2unix
RUN mkdir -p /app/templates

COPY grader.py /app/grader.py
COPY checks.sh /app/checks.sh
COPY templates/index.html /app/templates/index.html

COPY grader_id_rsa /root/grader_id_rsa
RUN dos2unix /root/grader_id_rsa && chmod 600 /root/grader_id_rsa

RUN chmod +x /app/checks.sh

EXPOSE 80

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]