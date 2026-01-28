FROM python:3.14.0b2-bookworm

RUN pip install Flask

COPY grader.py /grader.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY wordlist.txt /wordlist.txt

ENV token2=""

EXPOSE 80

CMD ["/entrypoint.sh"]