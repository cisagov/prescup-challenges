FROM python:3.14.0b2-bookworm

RUN pip install Flask
RUN apt update
RUN apt install -y dnsutils

COPY grader.py /grader.py

ENV token3=""

EXPOSE 80

CMD ["python3", "/grader.py"]