#!/usr/bin/env python3

# Usage: ./loki_client /path/to/scan

import os
import socket
import sys, time

host = '127.0.0.1'
port = 1337

try:
    path = sys.argv[1]
except:
    print('missing path')
    sys.exit(1)

if not os.path.isfile(path) and not os.path.isdir(path):
    print(path + 'not found')
    sys.exit(127)

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print('Could not create a socket')
    sys.exit()

try:
    client.connect((host, port))
except socket.error:
    print('Could not connect to server')
    sys.exit()

online = True
while online:
    data = sys.argv[1]
    client.sendall(data.encode())
    while True:
        message = client.recv(4096)
        if 'RESULT' in message.decode():
            print(message.decode())
            client.close()
            online = False
            break
        break

client.close()
