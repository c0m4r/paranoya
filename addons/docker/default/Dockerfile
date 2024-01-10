FROM python:3
WORKDIR /usr/src/app
RUN git clone https://github.com/c0m4r/Loki-daemonized.git .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 1337
CMD [ "python", "loki.py", "--listen-host", "0.0.0.0", "-d", "--nolog", "--intense", "-s", "20000"]
