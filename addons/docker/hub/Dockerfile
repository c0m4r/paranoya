FROM alpine:3.19
WORKDIR /loki
RUN apk add --no-cache bash gcc git musl-dev linux-headers openssl-dev python3 python3-dev py3-pip wget \
  && adduser -D loki \
  && git clone https://github.com/c0m4r/Loki-daemonized.git . \
  && ./deploy.sh \
  && rm -rfv .git .github .gitignore addons test \
  && chown -R loki:loki /loki \
  && apk del --no-cache gcc git musl-dev linux-headers openssl-dev python3-dev
EXPOSE 1337
USER loki
CMD [ "python3", "loki.py", "-d", "--listen-host", "0.0.0.0", "--noindicator", "--noprocscan", "--nolog" ]
