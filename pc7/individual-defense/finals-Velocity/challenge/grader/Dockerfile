FROM python:3.10-slim

RUN apt update && apt install -y nano vim ssh dos2unix pip
RUN pip install flask requests

RUN mkdir -p /root/.ssh
COPY pub_id_rsa_grader /root/.ssh/id_rsa.pub
COPY id_rsa_grader /root/.ssh/id_rsa
RUN dos2unix /root/.ssh/id_rsa && dos2unix /root/.ssh/id_rsa.pub
RUN chmod 600 /root/.ssh/id_rsa && chmod 644 /root/.ssh/id_rsa.pub

WORKDIR /grader
RUN mkdir -p /grader/static
COPY grader.py .
COPY grader.sh .
RUN chmod +x grader.sh
RUN dos2unix ./grader.py ./grader.sh

EXPOSE 80
CMD ["python", "grader.py"]
