# C2 replay listener — replays the DEEP#DOOR challenge-response handshake.
# The handler sends a random per-connection challenge string. The client
# (i.e. the competitor's script, replicating svc.py's auth routine) must
# reply with SHA256(challenge + base64("changeme123")). On match, the
# listener returns TOKEN5. On mismatch, the connection is closed.

FROM python:3.12-slim AS base

# Multi-stage so the source code is not present in the final image.
WORKDIR /build
COPY handler.py /build/handler.py

FROM python:3.12-slim
COPY --from=base /build/handler.py /opt/handler/handler.py
WORKDIR /opt/handler
EXPOSE 41243
CMD ["python3", "/opt/handler/handler.py"]
