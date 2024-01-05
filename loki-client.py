#!/usr/bin/env python3

# Usage: python3 loki_client.py test

import os
import socket
import sys

host = "127.0.0.1"
port = 1337

try:
    path = sys.argv[1]
except Exception:
    print("missing path")
    sys.exit(1)

try:
    auth = sys.argv[2]
except Exception:
    auth = ""

if not os.path.isfile(path) and not os.path.isdir(path):
    print(path + " not found")
    sys.exit(127)

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print("Could not create a socket")
    sys.exit(1)

try:
    client.connect((host, port))
except socket.error:
    print("Could not connect to server")
    sys.exit(1)

if auth:
    data = sys.argv[1] + " " + sys.argv[2]
else:
    data = sys.argv[1]

client.send(data.encode())
message = client.recv(2048)
print(message.decode())
client.close()
