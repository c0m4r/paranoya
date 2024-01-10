FROM alpine:3.19
RUN apk add --no-cache bash gcc git musl-dev linux-headers openssl-dev python3 python3-dev py3-pip wget
WORKDIR /opt
RUN git clone https://github.com/c0m4r/Loki-daemonized.git .
EXPOSE 1337
RUN python3 -m venv .
RUN /bin/bash -c "source bin/activate && pip3 install --no-cache-dir --upgrade pip setuptools wheel && pip3 install -r requirements.txt && ./upgrader.py --sigsonly"
CMD [ "/bin/bash", "-c", "source bin/activate && python3 loki.py -d --listen-host 0.0.0.0 --nolog --intense --csv"]
