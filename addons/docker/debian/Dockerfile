FROM debian:bookworm
RUN apt-get update \
 && apt-get -y install bash curl gcc git libssl-dev python3 python3-dev python3-pip python3-venv wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
RUN git clone https://github.com/c0m4r/paranoya.git .
EXPOSE 1337
RUN python3 -m venv .
RUN /bin/bash -c "source bin/activate \
 && pip3 install --no-cache-dir --upgrade pip setuptools wheel \
 && pip3 install -r requirements.txt \
 && ./upgrader.py --sigsonly"
CMD [ "/bin/bash", "-c", "source bin/activate && python3 paranoya.py -d --listen-host 0.0.0.0 --nolog --intense --csv"]
