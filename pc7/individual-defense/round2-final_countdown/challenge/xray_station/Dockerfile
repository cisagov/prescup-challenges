FROM python:3.10-slim

WORKDIR /xray

COPY xray.py ./

RUN pip install flask requests

CMD ["python", "xray.py"]
