FROM python:3.11-slim

WORKDIR /opt/meeting-room

COPY suitcase_gui.py ./suitcase_gui.py
COPY entrypoint.py ./entrypoint.py

RUN pip install --no-cache-dir flask

EXPOSE 8082

CMD ["python", "entrypoint.py"]
