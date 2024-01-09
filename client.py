#!/usr/bin/env python
"""
Loki client

Loki - Simple IOC Scanner Copyright (c) 2015 Florian Roth
Loki (daemonized) - Simple IOC and YARA Scanner fork (c) 2023 c0m4r

https://github.com/c0m4r/Loki-daemonized

Licensed under GPL 3.0
"""

import argparse
import os
import socket
import sys

# Parse Arguments
parser = argparse.ArgumentParser(
    description="Loki - Client", formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("-p", help="Path to scan", metavar="PATH")
parser.add_argument(
    "--host",
    help="Target daemon host",
    default="localhost",
)
parser.add_argument(
    "--port",
    help="Target daemon port",
    default=1337,
)
parser.add_argument(
    "--auth",
    metavar="AUTHKEY",
    help="Pass authkey if it is required",
)
parser.add_argument(
    "--check",
    action="store_true",
    help="Check if path exists before it is sent",
    default=False,
)

args = parser.parse_args()

if not args.p:
    print("Missing -p path")
    sys.exit(1)

if args.check:
    if not os.path.isfile(args.p) and not os.path.isdir(args.p):
        print(args.p + " not found")
        sys.exit(1)

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print("Could not create a socket")
    sys.exit(1)

try:
    client.connect((args.host, int(args.port)))
except socket.error:
    print("Could not connect to server")
    sys.exit(1)

if args.auth:
    data = args.p + " " + args.auth
else:
    data = args.p

client.send(data.encode())
message = client.recv(2048)
print(message.decode())
client.close()
