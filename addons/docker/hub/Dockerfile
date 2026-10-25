FROM alpine:3.21
COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /usr/local/bin/uv
ENV UV_NO_CACHE=1
WORKDIR /paranoya
RUN apk add --no-cache bash gcc git musl-dev linux-headers openssl-dev python3 python3-dev wget \
  && adduser -D paranoya \
  && git clone https://github.com/c0m4r/paranoya.git . \
  && ./deploy.sh \
  && rm -rfv .git .github .gitignore addons test /usr/local/bin/uv \
  && chown -R paranoya:paranoya /paranoya \
  && apk del --no-cache gcc git musl-dev linux-headers openssl-dev python3-dev
EXPOSE 1337
USER paranoya
CMD [ "python3", "paranoya.py", "-d", "--listen-host", "0.0.0.0", "--noindicator", "--noprocscan", "--nolog" ]
