FROM python:3.10-slim

WORKDIR /grader
COPY grader.py .
COPY testfile.sh .

RUN apt update && apt install -y nano vim ssh dos2unix pip
RUN pip install flask requests
COPY hospital_id_rsa /root/.ssh/hospital_id_rsa
RUN dos2unix /root/.ssh/hospital_id_rsa && chmod 600 /root/.ssh/hospital_id_rsa

EXPOSE 80
CMD ["python", "grader.py"]
