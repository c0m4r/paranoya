FROM ghcr.io/void-linux/void-glibc:20260401R1
RUN xbps-install -Su && xbps-install -Sy bash curl gcc git openssl-devel python3 python3-devel python3-pip python3-virtualenv wget
WORKDIR /opt
RUN git clone https://github.com/c0m4r/paranoya.git .
EXPOSE 1337
RUN python3 -m venv .
SHELL ["/bin/bash", "-c"]
RUN source bin/activate
RUN ./bin/pip3 install --no-cache-dir --upgrade pip==26.1
RUN ./bin/pip3 install --no-cache-dir --uploaded-prior-to=P14D --upgrade setuptools wheel
RUN ./bin/pip3 install --no-cache-dir --uploaded-prior-to=P14D --require-hashes -r requirements.lock.txt
RUN ./upgrader.py --sigsonly
CMD [ "/bin/bash", "-c", "source bin/activate && python3 paranoya.py -d --listen-host 0.0.0.0 --nolog --intense --csv"]
