FROM alpine:3.19
RUN apk add --no-cache bash python3 python3-dev py3-pip gcc musl-dev linux-headers openssl-dev
WORKDIR /opt
COPY Loki-daemonized ./
EXPOSE 1337
RUN python3 -m venv .
RUN /bin/bash -c "source bin/activate && pip3 install -r requirements.txt"
CMD [ "/bin/bash", "-c", "source bin/activate && python3 loki.py -d --listen-host 0.0.0.0 --nolog --force --intense --nolog --csv"]
