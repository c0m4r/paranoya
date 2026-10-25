FROM python:3
COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /usr/local/bin/uv
ENV UV_NO_CACHE=1
WORKDIR /usr/src/app
RUN git clone https://github.com/c0m4r/paranoya.git .
RUN uv sync --locked
EXPOSE 1337
CMD [ ".venv/bin/python", "paranoya.py", "--listen-host", "0.0.0.0", "-d", "--nolog", "--intense", "-s", "20000"]
