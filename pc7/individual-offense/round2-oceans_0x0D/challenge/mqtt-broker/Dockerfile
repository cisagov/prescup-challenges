FROM eclipse-mosquitto:2.0

# Explicit config to ensure the broker is reachable on the docker network and
# anonymous connections are allowed (Mosquitto 2.0 defaults are stricter).
COPY mosquitto.conf /mosquitto/config/mosquitto.conf

EXPOSE 1883
CMD ["mosquitto","-c","/mosquitto/config/mosquitto.conf"]
