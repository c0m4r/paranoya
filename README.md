<div align="center">

![/addons/img/loki-daemonized-icon.png](/addons/img/loki-daemonized-header.png)

## Loki (daemonized) - Simple IOC and YARA scanner for Linux

![Python](https://img.shields.io/badge/made%20with-python-blue?logo=python&logoColor=ffffff)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Test](https://github.com/c0m4r/Loki-daemonized/workflows/lint_python/badge.svg)](https://github.com/c0m4r/Loki-daemonized/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/c0m4r/loki-daemonized/badge)](https://www.codefactor.io/repository/github/c0m4r/loki-daemonized)

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![Flatpak](https://img.shields.io/badge/flatpak-%23488bd2.svg?style=for-the-badge&logo=flatpak&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)

</div>

A fork of [Loki - Simple IOC and YARA Scanner](https://github.com/Neo23x0/Loki), rewritten for Linux and modified to support single file scans, 
as well as a daemon mode to accept scans in client/server manner. It also includes some [other improvements](#New-features).

## Dependencies

[Python3](https://www.python.org/) 
| [colorama](https://pypi.org/project/colorama/) 
| [progressbar2](https://pypi.org/project/progressbar2/) 
| [psutil](https://pypi.org/project/psutil/) 
| [requests](https://pypi.org/project/requests/) 
| [yara-python](https://pypi.org/project/yara-python/) 
| [signature-base](https://github.com/Neo23x0/signature-base) 
| [reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules)

#### Alpine Linux

```
apk add bash gcc git linux-headers musl-dev openssl-dev python3 python3-dev py3-pip
```

#### Arch Linux

```
pacman -S bash gcc git python3 python-devtools python-pip
```

#### Void Linux

```
xbps-install -Sy bash gcc git openssl-devel python3 python3-devel python3-pip
```

#### Debian / Ubuntu / Linux Mint

```
apt -y install bash build-essential git libssl-dev python3 python3-dev python3-pip python3-venv
```

#### Rocky Linux / AlmaLinux

```
dnf install bash gcc git openssl-devel python3 python3-devel python3-pip
```

## Installation

#### Manual

```
git clone https://github.com/c0m4r/Loki-daemonized.git
cd Loki-daemonized
./deploy.sh
./loki.py --nolog --intense -p ./test
```

#### Docker

This repo comes with predefined docker files. The default one is based on [official python image](https://hub.docker.com/_/python), 
so running in docker should be as simple as:

```
git clone https://github.com/c0m4r/Loki-daemonized.git
cd Loki-daemonized/docker/default
docker compose up -d
```

However, to be able to scan anything outside docker you have to mount a volume pointing to a specific directory. Change docker-compose.yml accordingly.

There are also other [Dockerfiles](/addons/docker) available, based on different Linux distros.

#### Flatpak

DIY flatpak-builder files available [here](/addons/flatpak). Simply hit `./build.sh`.

Once it's ready, you can run Loki, passing arguments you need.

```
flatpak run org.flatpak.Loki-daemonized --intense -p ./test
```

Keep in mind that even though there is `--filesystem=host` set, 
some of the directories are [blacklisted](https://docs.flatpak.org/en/latest/sandbox-permissions.html#filesystem-access) under Flatpak Sandbox, preventing Loki from scanning them.

In order to scan one of them use an override. An example for /tmp dir:

```
flatpak override --user --filesystem=/tmp org.flatpak.Loki-daemonized
```

#### Compiled

For binary version of Loki-daemonized and its tools use ./build.sh script.

However, when possible, you should use bare python under venv, 
as it will allow you to get the latest versions of python modules and keep them up-to-date, 
as well as view and verify the source code.

#### Chroot

See: [Loki‐daemonized in chroot](https://github.com/c0m4r/Loki-daemonized/wiki/Loki%E2%80%90daemonized-in-chroot)

#### Android

See: [Loki‐daemonized on Android](https://github.com/c0m4r/Loki-daemonized/wiki/Loki%E2%80%90daemonized-on-Android)

## Daemonized usage

#### Server

Start as a daemon and bind on default localhost:1337

```
./loki.py -d -s 20000 --noindicator --csv --nolog --intense
```

You can also change default bind address/port with `--listen-host` and `--listen-port` args. Check `--help` for details.

Check example [init files](/addons/etc) for OpenRC and systemd integration.

#### Client

```
./client.py -p /path/to/scan
```

As for now the server accepts plain path and an optional space-separated authkey.

```
echo "./test" | nc localhost 1337 ; echo
echo "./test authkey" | nc localhost 1337 ; echo
```

Possible responses:

| Answer                               | Level   | Score  |
| ------------------------------------ | ------- | ------ |
| RESULT: Indicators detected!         | ALERT   | >= 100 |
| RESULT: Suspicious objects detected! | WARNING | >= 60  |
| RESULT: SYSTEM SEEMS TO BE CLEAN.    | NOTICE  | >= 40  |

In `--auth` mode it will respond with `authorization required` if authkey was not sent or `unauthorized` if authkey is invalid.

## New features

* Focuses on Linux
* Single file scan if given path is a file
* Daemon mode `-d` with listening socket `--listen-host 127.0.0.1` `--listen-port 1337` accepting scans requested from client.py
* PID file `loki.pid` is created in the program directory if running in daemon mode, you change its path with `--pidfile /path/to/pidfile`
* Optional auth key `--auth somethingRandomHere` in daemon mode (just a dumb string authorization, can be intercepted and read from the process list)
* You can disable one or more yara files, f.e. `--disable-yara-files apt_vpnfilter.yar,yara_mixed_ext_vars.yar`
* Exclude files by hash as proposed by [rafaelarcanjo](https://github.com/rafaelarcanjo) in [Neo23x0/Loki/pull/204](https://github.com/Neo23x0/Loki/pull/204). See: [excludes.cfg](/config/excludes.cfg)
* Initial implementation of process scanning under Linux (scan_processes_linux()):
  * File Name Checks: works with signature-base/iocs/filename-iocs.txt (note: linux iocs missing by default)
  * Process connections: for now, it only shows detected connections per process
  * Process Masquerading Detection: reports non-empty /proc/PID/maps of processes that uses square brackets in their cmdlines

## Screenshot

![/addons/img/loki-daemonized-screen3.png](/addons/img/loki-daemonized-screen-3.1.0.png)

## Usage

Run a program with --help to view usage information.

See: [Usage](https://github.com/c0m4r/Loki-daemonized/wiki/Usage)

## License

```
Loki (daemonized): Simple IOC and YARA Scanner
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
```

## DISCLAIMER

> USE AT YOUR OWN RISK & DON'T BE EVIL
