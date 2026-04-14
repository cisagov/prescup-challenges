FROM python:3.10-slim

WORKDIR /infusion

COPY infusion.py ./

RUN pip install flask requests

CMD ["python", "infusion.py"]
#CMD ["sleep", "infinity"]