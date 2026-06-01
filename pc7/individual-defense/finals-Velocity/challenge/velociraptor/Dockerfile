FROM wlambert/velociraptor

COPY dos2unix /usr/bin/dos2unix
RUN chmod +x /usr/bin/dos2unix
COPY server.config.yaml /velociraptor/server.config.yaml
RUN chmod 644 /velociraptor/server.config.yaml
RUN dos2unix /velociraptor/server.config.yaml

RUN chmod +x /opt/velociraptor/linux/velociraptor
RUN /opt/velociraptor/linux/velociraptor --config /velociraptor/server.config.yaml user add --role=administrator admin admin

EXPOSE 8000 8001 8889
