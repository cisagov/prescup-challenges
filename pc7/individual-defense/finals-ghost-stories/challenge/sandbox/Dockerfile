# Analysis sandbox — Jupyter with Volatility 3, regipy, python-evtx,
# and deobfuscation helpers. Competitors run the recovered svc.py
# extraction routine in-place here; the network egress is restricted
# to the challenge's competitor_net only (no external egress at
# runtime) so even a fully-armed implant cannot reach its real C2.

FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        file \
        git \
        unzip \
        xxd \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        jupyterlab==4.* \
        volatility3 \
        regipy \
        python-evtx \
        python-registry \
        pefile \
        oletools \
        capstone

# Pre-baked deobfuscation helpers + notebook starter so competitors have
# a working analysis surface immediately.
COPY notebooks/ /home/analyst/notebooks/
COPY helpers/   /home/analyst/helpers/

RUN useradd -m analyst && chown -R analyst:analyst /home/analyst

USER analyst
WORKDIR /home/analyst

EXPOSE 8888

CMD ["jupyter", "lab", \
     "--ip=0.0.0.0", \
     "--port=8888", \
     "--no-browser", \
     "--ServerApp.token=", \
     "--ServerApp.password=", \
     "--ServerApp.disable_check_xsrf=True", \
     "--ServerApp.root_dir=/home/analyst"]
