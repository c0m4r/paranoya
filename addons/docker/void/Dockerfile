FROM ghcr.io/void-linux/void-glibc:20260401R1
RUN xbps-install -Su && xbps-install -Sy bash curl gcc git openssl-devel python3 python3-devel wget
COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /usr/local/bin/uv
ENV UV_NO_CACHE=1
WORKDIR /opt
RUN git clone https://github.com/c0m4r/paranoya.git .
EXPOSE 1337
RUN uv sync --locked
RUN .venv/bin/python upgrader.py --sigsonly
CMD [ ".venv/bin/python", "paranoya.py", "-d", "--listen-host", "0.0.0.0", "--nolog", "--intense", "--csv"]
