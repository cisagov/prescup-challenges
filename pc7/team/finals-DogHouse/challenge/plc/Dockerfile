FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ncat tcpdump \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pymodbus==3.6.6


COPY plc_server.py /plc_server.py
RUN chmod +x /plc_server.py

EXPOSE 5020

CMD ["python3", "/plc_server.py"]
