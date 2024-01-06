FROM ghcr.io/void-linux/void-glibc:latest
RUN xbps-install -Su && xbps-install -Sy bash curl gcc git openssl-devel python3 python3-devel python3-pip python3-virtualenv wget
WORKDIR /opt
RUN git clone https://github.com/c0m4r/Loki-daemonized.git .
EXPOSE 1337
RUN python3 -m venv .
RUN /bin/bash -c "source bin/activate && pip3 install --no-cache-dir --upgrade pip setuptools wheel && pip3 install -r requirements.txt && ./loki-upgrader.py --sigsonly --nolog"
CMD [ "/bin/bash", "-c", "source bin/activate && python3 loki.py -d --listen-host 0.0.0.0 --nolog --force --intense --nolog --csv"]
