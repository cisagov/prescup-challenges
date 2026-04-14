FROM python:3.10-slim

WORKDIR /attacker

COPY exploit.py .
COPY entrypoint.sh .

RUN pip install requests && chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]
