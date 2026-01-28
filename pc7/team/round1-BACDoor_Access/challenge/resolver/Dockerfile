FROM python:3.13.4-slim

COPY ./resolver.py /resolver.py
RUN touch /devices.json

CMD ["python3", "/resolver.py"]