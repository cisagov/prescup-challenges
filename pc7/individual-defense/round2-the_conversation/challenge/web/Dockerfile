FROM python:alpine

# Install bash
RUN apk add --no-cache bash
# Install vim and nano
RUN apk add --no-cache vim nano emacs
# Install curl for testing
RUN apk add --no-cache curl

ADD web/start.sh /app/start.sh
ADD bin/template.docm /data/template.docm

RUN chown -R root:root /app/
RUN chmod u+x /app/*

RUN chown -R root:root /data/
RUN chmod u+x /data/*

CMD [ "/app/start.sh" ]
