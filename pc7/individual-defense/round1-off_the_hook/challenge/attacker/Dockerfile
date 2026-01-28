FROM python:3.13.4-slim

# Install Flask and other dependencies
RUN pip install flask requests
RUN pip install redis paramiko

# Copy app code
COPY ./worm* /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run Flask server
CMD ["python", "c2_server.py"]

ENTRYPOINT ["/entrypoint.sh"]