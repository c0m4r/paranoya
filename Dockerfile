FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 1337

CMD [ "python", "loki.py", "--listen-host", "0.0.0.0", "-d", "--nolog", "--force", "--intense", "-s", "20000"]
