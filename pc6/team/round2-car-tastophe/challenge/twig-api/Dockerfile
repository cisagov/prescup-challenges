FROM python:3.8-slim-buster

WORKDIR /twig

COPY api.py api.py
COPY generateRandomTrips.py generateRandomTrips.py
RUN pip install gunicorn flask
RUN python generateRandomTrips.py

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "api:app"]

