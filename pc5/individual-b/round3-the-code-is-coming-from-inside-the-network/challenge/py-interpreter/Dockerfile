FROM python:latest

WORKDIR /home/user/Desktop/container/

COPY . ./
RUN pip install --no-index --find-links=./ --no-cache-dir -r ./requirements.txt --use-pep517

CMD ["python3","./server.py"]