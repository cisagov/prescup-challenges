FROM python:3.10-slim
WORKDIR /gen
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsndfile1 fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gen_audio_utils.py gen_audio_utils.py
COPY gen_pcap_utils.py gen_pcap_utils.py
COPY gen_all.py gen_all.py
