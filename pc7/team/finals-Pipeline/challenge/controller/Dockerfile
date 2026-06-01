FROM gitea/act_runner:latest

USER root

RUN apk add ansible openssh-server openssh-client sudo dos2unix bash curl jq git procps nmap-ncat coreutils

RUN mkdir -p /var/run/sshd

# add ansibleadm user
RUN adduser ansibleadm -s /bin/bash -D
RUN adduser ansibleadm wheel
RUN passwd -u ansibleadm

# add runner user
RUN adduser runner -s /bin/bash -D

COPY config.yaml /home/runner/config.yaml
RUN dos2unix /home/runner/config.yaml \
  && chown runner:runner /home/runner/config.yaml

COPY setup.sh /tmp/setup.sh
RUN chmod +x /tmp/setup.sh \
  && chown runner:runner /tmp/setup.sh \
  && dos2unix /tmp/setup.sh

# ansibleadm ssh keys and playbooks
RUN mkdir -p /home/ansibleadm/.ssh \
  && chmod 700 /home/ansibleadm/.ssh

COPY pub_id_rsa /home/ansibleadm/.ssh/id_rsa.pub
COPY id_rsa /home/ansibleadm/.ssh/id_rsa
RUN chmod 600 /home/ansibleadm/.ssh/id_rsa \
  && chmod 644 /home/ansibleadm/.ssh/id_rsa.pub

COPY pub_id_ed25519_grader /home/ansibleadm/.ssh/authorized_keys
RUN chmod 600 /home/ansibleadm/.ssh/authorized_keys

RUN dos2unix /home/ansibleadm/.ssh/*

RUN mkdir -p /etc/ansible
COPY ansible.cfg /etc/ansible/ansible.cfg
RUN dos2unix /etc/ansible/ansible.cfg \
  && chmod 644 /etc/ansible/ansible.cfg

RUN mkdir -p /opt/playbooks
COPY system_check_playbook.yml /opt/playbooks/system_check_playbook.yml
RUN chmod 666 /opt/playbooks/system_check_playbook.yml

COPY tools_ftp_playbook.yml /opt/playbooks/tools_ftp_playbook.yml
RUN chmod 600 /opt/playbooks/tools_ftp_playbook.yml

COPY inventory.ini /opt/playbooks/inventory.ini
RUN chmod 644 /opt/playbooks/inventory.ini

COPY vault_pass.txt /opt/playbooks/vault_pass.txt
RUN chmod 600 /opt/playbooks/vault_pass.txt

COPY vault.yml /opt/playbooks/vault.yml
RUN chmod 600 /opt/playbooks/vault.yml

RUN chown -R ansibleadm:ansibleadm /opt/playbooks \
  && dos2unix /opt/playbooks/*

COPY run_playbook.sh /home/ansibleadm/run_playbook.sh
RUN chmod 700 /home/ansibleadm/run_playbook.sh \
  && dos2unix /home/ansibleadm/run_playbook.sh

# setup terraform on runner 
RUN mkdir -p /home/runner/.terraform.d/plugins \
  && chmod -R 700 /home/runner/.terraform.d \
  && chown -R runner:runner /home/runner

COPY terraform /usr/local/bin/terraform
RUN chmod +x /usr/local/bin/terraform

# grading scripts
COPY grader_script.sh /home/ansibleadm/grader_script.sh
RUN chmod 500 /home/ansibleadm/grader_script.sh \
  && dos2unix /home/ansibleadm/grader_script.sh

COPY grader.py /home/ansibleadm/grader.py
RUN chmod 500 /home/ansibleadm/grader.py \
  && dos2unix /home/ansibleadm/grader.py

COPY grader_playbook.yml /home/ansibleadm/grader_playbook.yml
RUN chmod 500 /home/ansibleadm/grader_playbook.yml \
  && dos2unix /home/ansibleadm/grader_playbook.yml

COPY md5_grader.sh /home/ansibleadm/md5_grader.sh
RUN chmod 500 /home/ansibleadm/md5_grader.sh \
  && dos2unix /home/ansibleadm/md5_grader.sh

# Final ownership fixes
RUN chown -R ansibleadm:ansibleadm /home/ansibleadm
RUN chmod o= /home/ansibleadm

COPY entrypoint.sh /entrypoint.sh
RUN chmod 700 /entrypoint.sh
RUN dos2unix /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
