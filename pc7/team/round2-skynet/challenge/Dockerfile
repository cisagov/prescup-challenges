FROM node:24-alpine

# Install bash
RUN apk add --no-cache bash vim dos2unix

# Install deps
ADD src/package.json /app/package.json
#RUN mkdir -p /app
RUN mkdir -p /app/uploads
#COPY src/package.json /app/package.json
WORKDIR /app
RUN corepack enable pnpm
RUN pnpm install

# Add scripts
# ADD src/ /app/
COPY src/ /app/

RUN chown -R root:root /app/
RUN chmod u+x /app/*
RUN dos2unix /app/start.sh  /app/*.js

COPY web/ /app/
RUN dos2unix /app/server.js
RUN chmod 755 /app/server.js

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN dos2unix /entrypoint.sh

COPY coords.bin /app/uploads/coords.bin
RUN chmod 644 /app/uploads/coords.bin

ENTRYPOINT [ "/entrypoint.sh" ]
