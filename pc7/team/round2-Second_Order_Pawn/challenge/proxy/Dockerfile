FROM nginx:1.29.0

COPY nginx.conf /etc/nginx/nginx.conf
RUN apt update && apt install -y wait-for-it
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/bin/wait-for-it /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
