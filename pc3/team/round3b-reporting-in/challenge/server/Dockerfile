FROM python:3.9-alpine

WORKDIR /usr/src/app

COPY Pipfile* ./

RUN pip install --no-cache-dir pipenv 
RUN pipenv install --system --deploy --clear

COPY src src

CMD ["uvicorn", "--app-dir", "src", "--host", "0.0.0.0", "app:app"]
EXPOSE 8000/tcp
