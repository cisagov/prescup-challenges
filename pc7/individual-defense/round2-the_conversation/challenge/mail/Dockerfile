FROM python:alpine

# Install bash
RUN apk add --no-cache bash
# Install vim and nano
RUN apk add --no-cache vim nano emacs
# Install curl for testing
RUN apk add --no-cache curl

# Install python deps
ADD mail/app/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt --break-system-packages

RUN mkdir /data/
RUN mkdir /attachments/

# Set up malicious attachment
ADD bin/datasheet.docx /payloads/datasheet.docx
RUN chown -R root:root /payloads/

# Set up application
ADD mail/app/ /app/
RUN chown -R root:root /app/
RUN chmod u+x /app/src/*

# Create email attachments at build time to speed up container start time
RUN python /app/src/attachments.py

CMD [ "/app/start.sh" ]

