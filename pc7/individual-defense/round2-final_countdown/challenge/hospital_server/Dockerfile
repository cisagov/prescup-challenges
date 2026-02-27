FROM ubuntu:20.04

WORKDIR /app

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y tcpdump gpg ssh sudo nano openssl dos2unix openssh-server python3 pip

COPY app.py ./
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

RUN mkdir -p /var/log/hospital
RUN mkdir -p /data
COPY datagen.py /data/
# Install Flask
RUN pip install flask requests faker
WORKDIR /data
RUN python3 datagen.py
RUN rm datagen.py

RUN useradd -m -s /usr/bin/bash user ; echo "user:password" | chpasswd ; usermod -aG sudo user
RUN useradd -m grader -s /bin/bash && mkdir /home/grader/.ssh && usermod -aG sudo grader && echo "grader ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
#ssh key
COPY id_rsa /home/grader/.ssh/
COPY id_rsa.pub /home/grader/.ssh
RUN  dos2unix /home/grader/.ssh/id_rsa* && chmod 600 /home/grader/.ssh/id_rsa*
RUN cat /home/grader/.ssh/id_rsa.pub > /home/grader/.ssh/authorized_keys \
    && chown -R grader:grader /home/grader/.ssh \
    && chmod 600 /home/grader/.ssh/id_rsa \
    && chmod 611 /home/grader/.ssh/id_rsa.pub \
    && chmod 600 /home/grader/.ssh/authorized_keys 

WORKDIR /app
EXPOSE 80

CMD ["/app/entrypoint.sh"]
