FROM python:3.10-slim

RUN apt update && apt install -y nano vim ssh dos2unix pip
RUN pip install flask requests

WORKDIR /grader
RUN mkdir -p /grader/static
COPY grader.py .
COPY testfile.sh .
RUN chmod +x testfile.sh
RUN dos2unix ./grader.py ./testfile.sh
COPY custom_backdoor /grader/static/custom_backdoor

COPY pub_id_ed25519_grader /root/.ssh/id_ed25519.pub
COPY id_ed25519 /root/.ssh/id_ed25519
RUN dos2unix /root/.ssh/id_ed25519 && dos2unix /root/.ssh/id_ed25519.pub
RUN chmod 600 /root/.ssh/id_ed25519 && chmod 644 /root/.ssh/id_ed25519.pub

EXPOSE 80
CMD ["python", "grader.py"]
