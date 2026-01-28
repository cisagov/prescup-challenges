FROM ubuntu:24.04

# Install dependencies
RUN apt update && apt install -y python3 python3-pip nginx git

# Install Python requirements
RUN apt install -y python3-flask gunicorn python3-pymysql python3-tinydb python3-cryptography
RUN pip install mysql-connector-python --break-system-packages

RUN apt install -y wait-for-it

# Set up working directory
WORKDIR /app
COPY app/ /app
COPY git/ /git

# Set up Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Allow nginx to serve hidden files like .git
RUN sed -i 's|http {|http {\n    server_tokens off;|' /etc/nginx/nginx.conf

# Create entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]