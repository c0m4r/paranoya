FROM debian:bookworm
RUN apt update && apt -y install bash python3 python3-dev python3-pip python3-venv libssl-dev
WORKDIR /opt
COPY Loki-daemonized ./
EXPOSE 1337
RUN python3 -m venv .
RUN /bin/bash -c "source bin/activate && pip3 install -r requirements.txt && ./loki-upgrader.py --sigsonly --nolog"
CMD [ "/bin/bash", "-c", "source bin/activate && python3 loki.py -d --listen-host 0.0.0.0 --nolog --force --intense --nolog --csv"]
