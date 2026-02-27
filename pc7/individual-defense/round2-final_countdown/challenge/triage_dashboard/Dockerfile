FROM python:3.10-slim

WORKDIR /triage

COPY triage.py ./

RUN pip install flask requests

CMD ["python", "triage.py"]
