#!/usr/bin/env python
"""
Loki (daemonized) client
https://github.com/c0m4r/Loki-daemonized

Loki (daemonized): Simple IOC and YARA Scanner for Linux®
Copyright (c) 2015-2023 Florian Roth
Copyright (c) 2023-2024 c0m4r

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Linux® is the registered trademark of Linus Torvalds
in the U.S. and other countries.
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
