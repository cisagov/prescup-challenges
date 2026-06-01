FROM python:3.10-slim

RUN apt update && apt install -y nano vim ssh dos2unix pip ncat curl
RUN pip install flask requests

WORKDIR /grader
RUN mkdir -p /grader/static
COPY grader.py .
COPY grader.sh .
RUN chmod +x grader.sh
RUN dos2unix ./grader.py ./grader.sh

EXPOSE 80
CMD ["python", "grader.py"]
