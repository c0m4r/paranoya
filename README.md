![img/loki-daemonized-icon.png](img/loki-daemonized-icon.png)

## Loki (daemonized) - Simple IOC and YARA Scanner fork

A fork of [Loki - Simple IOC and YARA Scanner](https://github.com/Neo23x0/Loki), modified to support single file scan, as well as a daemon mode to accept scans in client/server manner.

The idea is that we can load all the rules once and then perform only individual file scans, which significantly reduces the load on hardware resources. This way, we can use Loki to scan, for example, files uploaded to the server.

Modifications tries to preserve original functionality, although I only care about Linux, so I do not guarantee compatibility with other platforms.

## Dependencies

* [Python3](https://www.python.org/)
  * [colorama](https://pypi.org/project/colorama/)
  * [future](https://pypi.org/project/future/)
  * [netaddr](https://pypi.org/project/netaddr/)
  * [psutil](https://pypi.org/project/psutil/)
  * [rfc5424-logging-handler](https://pypi.org/project/rfc5424-logging-handler/)
  * [yara-python](https://pypi.org/project/yara-python/)

#### Alpine Linux

```
apk add bash python3 python3-dev py3-pip gcc musl-dev linux-headers openssl-dev
```

## Installation

```bash
cd /opt
git clone https://github.com/c0m4r/Loki-daemonized.git
cd Loki-daemonized
python3 -m venv .
. bin/activate
pip3 install -r requirements.txt
./loki-upgrader.py --sigsonly --nolog
python3 loki.py --nolog --intense --force -p ./test
deactivate
```

## Patch file

Patch file contains changes made to original loki.py.

To apply the patch on original Loki you have to convert loki.py before and after due to DOS line-ending characters used by original author, which the patch does not have.

```bash
wget https://github.com/Neo23x0/Loki/blob/5b7175882a9b7247714b47347c2f9dccdf38d894/loki.py
dos2unix loki.py
patch < loki-daemonized.patch
unix2dos loki.py
```

## Daemonized usage

#### Daemon (server)

Start as a daemon and bind on default localhost:1337

```bash
cd Loki-daemonized
. bin/activate
python3 loki.py -d -s 20000 --noindicator --csv --nolog --intense --force &> /dev/null &
deactivate
```

You can also change default bind address/port with `--listen-host` and `--listen-port` args. Check `--help` for details.

Check example [/etc/init.d/loki](/etc/init.d/loki) for OpenRC integration.

#### Client

```
python3 loki_client.py /path/to/scan
```

## Changes

* Focuses on Linux
* Single file scan if given path is a file
* Daemon mode (-d) with listening socket (--listen-host, --listen-port) accepting scans requested from loki_client.py
* Optional auth key (--auth) in daemon mode (just a dumb string authorization, can be intercepted and read from the process list)

Derived from https://github.com/Neo23x0/Loki/blob/5b7175882a9b7247714b47347c2f9dccdf38d894/loki.py

Diff: [loki-daemonized.patch](loki-daemonized.patch)

## Screenshots

![img/loki-daemonized-screen1.png](img/loki-daemonized-screen1.png)

With auth:

![img/loki-daemonized-screen2.png](img/loki-daemonized-screen2.png)

---
## Licensed under GPL 3.0
* Loki - Simple IOC Scanner Copyright (c) 2015 Florian Roth
* Loki (daemonized) - Simple IOC and YARA Scanner fork (c) 2023 c0m4r

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
