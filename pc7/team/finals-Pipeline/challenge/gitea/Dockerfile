FROM gitea/gitea:1.25.3

USER root

RUN apk add --no-cache bash curl git jq openssh dos2unix

COPY app.ini.template /app.ini.template
COPY entrypoint.sh /entrypoint.sh
COPY bootstrap.sh /bootstrap.sh

RUN mkdir -p /seed/test/.gitea/workflows
RUN mkdir -p /seed/dev/.gitea/workflows
RUN mkdir -p /seed/dev/providers
RUN mkdir -p /seed/dev/consumers
RUN touch /seed/dev/providers/.gitkeep
RUN touch /seed/dev/consumers/.gitkeep
RUN mkdir -p /seed/infra/.gitea/workflows

COPY test-ci.yml /seed/test/.gitea/workflows/test-ci.yml
COPY dev-ci.yml /seed/dev/.gitea/workflows/dev-ci.yml  
COPY infra-ci.yml /seed/infra/.gitea/workflows/infra-ci.yml
RUN dos2unix /seed/test/.gitea/workflows/test-ci.yml
RUN dos2unix /seed/dev/.gitea/workflows/dev-ci.yml
RUN dos2unix /seed/infra/.gitea/workflows/infra-ci.yml

RUN chmod +x /entrypoint.sh /bootstrap.sh
RUN dos2unix /entrypoint.sh /bootstrap.sh

ENTRYPOINT ["/entrypoint.sh"]
