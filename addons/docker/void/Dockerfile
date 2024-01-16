FROM ghcr.io/void-linux/void-glibc:20231230r1
RUN xbps-install -Su && xbps-install -Sy bash curl gcc git openssl-devel python3 python3-devel python3-pip python3-virtualenv wget
WORKDIR /opt
RUN git clone https://github.com/c0m4r/paranoya.git .
EXPOSE 1337
RUN python3 -m venv .
RUN /bin/bash -c "source bin/activate && pip3 install --no-cache-dir --upgrade pip setuptools wheel && pip3 install -r requirements.txt && ./upgrader.py --sigsonly"
CMD [ "/bin/bash", "-c", "source bin/activate && python3 paranoya.py -d --listen-host 0.0.0.0 --nolog --intense --csv"]
