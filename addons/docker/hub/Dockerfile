FROM alpine:3.19
WORKDIR /paranoya
RUN apk add --no-cache bash gcc git musl-dev linux-headers openssl-dev python3 python3-dev py3-pip wget \
  && adduser -D paranoya \
  && git clone https://github.com/c0m4r/paranoya.git . \
  && ./deploy.sh \
  && rm -rfv .git .github .gitignore addons test \
  && chown -R paranoya:paranoya /paranoya \
  && apk del --no-cache gcc git musl-dev linux-headers openssl-dev python3-dev
EXPOSE 1337
USER paranoya
CMD [ "python3", "paranoya.py", "-d", "--listen-host", "0.0.0.0", "--noindicator", "--noprocscan", "--nolog" ]
