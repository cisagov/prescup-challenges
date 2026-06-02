FROM gitea/act_runner:latest

USER root

RUN apk add --no-cache dos2unix bash curl jq git procps nmap-ncat coreutils 

RUN adduser runner -s /bin/bash -D

# COPY .profile /home/runner/.profile
# RUN dos2unix /home/runner/.profile \
#   && chown runner:runner /home/runner/.profile

# COPY .profile /root/.profile
# RUN dos2unix /root/.profile \
#   && chown root:root /root/.profile

# COPY config.yaml.template /config.yaml.template
# RUN dos2unix /config.yaml.template \
#   && chown runner:runner /config.yaml.template

COPY config.yaml /home/runner/config.yaml
RUN dos2unix /home/runner/config.yaml \
  && chown runner:runner /home/runner/config.yaml

COPY var_check.sh /home/runner/var_check.sh
RUN chmod +x /home/runner/var_check.sh \
  && dos2unix /home/runner/var_check.sh \
  && chown runner:runner /home/runner/var_check.sh

COPY setup.sh /tmp/setup.sh
RUN chmod +x /tmp/setup.sh \
  && chown runner:runner /tmp/setup.sh \
  && dos2unix /tmp/setup.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
  && chown runner:runner /entrypoint.sh \
  && dos2unix /entrypoint.sh

USER runner
WORKDIR /home/runner
ENTRYPOINT ["/entrypoint.sh"]
