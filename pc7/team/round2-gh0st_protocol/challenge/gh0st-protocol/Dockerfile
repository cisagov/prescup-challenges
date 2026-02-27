FROM python:3.11-slim
WORKDIR /opt/gh0st
COPY ghost_server.py ./ghost_server.py
COPY generate_ghost_code.py ./generate_ghost_code.py
EXPOSE 4000
CMD ["python", "-u", "ghost_server.py"]

