<div align="center">

![paranoya](https://github.com/c0m4r/paranoya/assets/6292788/ba51b76d-49b4-42b7-9786-a92e6eef0060)

## paranoya: Simple IOC and YARA scanner for Linux®

![Python](https://img.shields.io/badge/made%20with-python-blue?logo=python&logoColor=ffffff)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Test](https://github.com/c0m4r/paranoya/workflows/lint_python/badge.svg)](https://github.com/c0m4r/paranoya/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/c0m4r/paranoya/badge)](https://www.codefactor.io/repository/github/c0m4r/paranoya)

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/c0m4r/paranoya)
[![Flatpak](https://img.shields.io/badge/flatpak-%23488bd2.svg?style=for-the-badge&logo=flatpak&logoColor=white)](https://github.com/c0m4r/paranoya?tab=readme-ov-file#flatpak)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/c0m4r/paranoya/wiki/paranoya-on-Android)

</div>

A fork of [Loki - Simple IOC and YARA Scanner](https://github.com/Neo23x0/Loki), rewritten for Linux and modified to support single file scans, 
as well as a daemon mode to accept scans in a client/server manner. It also includes some [other improvements](#New-features).

## Dependencies

#### Python modules

[colorama](https://pypi.org/project/colorama/) 
| [progressbar2](https://pypi.org/project/progressbar2/) 
| [psutil](https://pypi.org/project/psutil/) 
| [requests](https://pypi.org/project/requests/) 
| [yara-python](https://pypi.org/project/yara-python/)

#### Base YARA rules

[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) 
| [reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules)

#### Custom YARA rules

[elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) 
| [PhishingKit-Yara-Rules](https://github.com/t4d/PhishingKit-Yara-Rules) 
| [malpedia/signator-rules](https://github.com/malpedia/signator-rules) 
| [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge)

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
xbps-install -Sy bash gcc git openssl-devel python3 python3-devel
```

#### Debian / Ubuntu / Linux Mint

```
apt -y install gcc git libssl-dev python3 python3-dev python3-venv
update-alternatives --install /usr/bin/python python /usr/bin/python3 1
```

#### Rocky Linux / AlmaLinux

```
dnf install bash gcc git openssl-devel python3 python3-devel python3-pip
```

## Installation

#### Manual

```
git clone https://github.com/c0m4r/paranoya.git
cd paranoya
./deploy.sh
./paranoya.py --nolog --intense -p ./test
```

#### Docker

Now available on the [Docker Hub](https://hub.docker.com/r/c0m4r/paranoya) 
and [Github Packages](https://github.com/c0m4r/paranoya/pkgs/container/paranoya).

```
docker run --name paranoya -v /tmp:/tmp -p 127.0.0.1:1337:1337 -d c0m4r/paranoya
```

You can also build the image yourself. This repo comes with predefined Docker files. 
The default one is based on an [official Python image](https://hub.docker.com/_/python), 
so running it should be as simple as:

```
git clone https://github.com/c0m4r/paranoya.git
cd paranoya/addons/docker/default
docker compose up -d
```

However, to be able to scan anything outside of Docker, 
you have to mount a volume pointing to a specific directory. 
Change docker-compose.yml accordingly.

There are other [Dockerfiles](/addons/docker) available, based on different Linux distros.

#### Flatpak

DIY flatpak-builder files are available [here](/addons/flatpak).

```
git clone https://github.com/c0m4r/paranoya.git
cd paranoya/addons/flatpak
./build.sh
```

Once it's ready, you can run paranoya, passing the arguments you need.

```
flatpak run org.flatpak.paranoya --intense -p ./test
```

Keep in mind that even though there is `--filesystem=host` set, 
some of the directories are [blacklisted](https://docs.flatpak.org/en/latest/sandbox-permissions.html#filesystem-access) 
under Flatpak Sandbox, preventing paranoya from scanning them.

In order to scan one of them, use an override. An example for /tmp dir:

```
flatpak override --user --filesystem=/tmp org.flatpak.paranoya
```

#### Compiled

For the binary version of paranoya and its tools, use the `./build.sh` script.

However, when possible, you should use bare python under venv, 
as it will allow you to get the latest versions of python modules and keep them up-to-date, 
as well as view and verify the source code.

#### Chroot

See: [paranoya in chroot](https://github.com/c0m4r/paranoya/wiki/paranoya-in-chroot)

#### Android

See: [paranoya on Android](https://github.com/c0m4r/paranoya/wiki/paranoya-on-Android)

#### FreeBSD

See: [paranoya-on-FreeBSD](https://github.com/c0m4r/paranoya/wiki/paranoya-on-FreeBSD)

## Daemonized usage

#### Server

Start as a daemon and bind on the default localhost:1337

```
./paranoya.py -d -s 20000 --noindicator --csv --nolog --intense
```

You can also change default bind address/port with `--listen-host` 
and `--listen-port` args. Check `--help` for details.

Check example [init files](/addons/etc) for OpenRC and systemd integration.

#### Client

```
./client.py -p /path/to/scan
```

As of now, the server accepts a plain path and an optional space-separated auth key.

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

* Rewritten for Linux
* A single file scan if a given path is a file
* Daemon mode `-d` with listening socket `--listen-host 127.0.0.1` `--listen-port 1337`
  accepting scans requested from client.py
  * PID file `paranoya.pid` is created in the program directory if running in daemon mode,
    you change its path with `--pidfile /path/to/pidfile`
  * Optional auth key `--auth somethingRandomHere` in daemon mode
    (just a dumb string authorization, can be intercepted and read from the process list)
* You can disable one or more yara files, f.e. `--disable-yara-files apt_vpnfilter.yar,yara_mixed_ext_vars.yar`
* Exclude files by hash as proposed by [rafaelarcanjo](https://github.com/rafaelarcanjo)
  in [Neo23x0/Loki/pull/204](https://github.com/Neo23x0/Loki/pull/204). See: [excludes.cfg](/config/excludes.cfg)
* Initial implementation of process scanning under Linux (scan_processes_linux()):
  * File Name Checks: works with signature-base/iocs/filename-iocs.txt (note: linux iocs missing by default)
  * Process connections: for now, it only shows detected connections per process
  * Process Masquerading Detection: reports non-empty /proc/PID/maps of processes that uses square brackets in their cmdlines
* Progress bar (experimental) can be enabled with --progress
* Force paranoya to follow symlinks (be aware: may lead to RAM overflow) with --followlinks
* Custom yara rules sources
  * Some additional YARA rule sources have been added and you can also choose your own
  * Custom yara ruleset dir can be set with --custom signature-custom/yara/name
  * To avoid conflicts between rules, it's recommended to use only one source at a time

## Usage

Run a program with --help to view usage information.

See: [Usage](https://github.com/c0m4r/paranoya/wiki/Usage)

## Custom signatures

Apart from the signature-base there are some example 
custom signature rulesets being pulled by the upgrader script.

Custom signatures can be used independently as a supplement, 
but you should avoid mixing the rule sources, as this may lead to conflicts between rules.

Use `--custom` to point the scanner to a different directory where the rules are stored. 
It will process all the .yar and .yara stored in that directory; don't point to a file, as this won't work.

Example usage of the custom ruleset:

```
./paranoya.py --intense --progress -p ./sample/webshell/ --custom signature-custom/yara/protections-artifacts-main/
```

These additional custom YARA rules has been proven to work* with paranoya:

* [SupportIntelligence/Icewater](https://github.com/SupportIntelligence/Icewater)
* [intezer/yara-rules](https://github.com/intezer/yara-rules)
* [jeFF0Falltrades/YARA-Signatures](https://github.com/jeFF0Falltrades/YARA-Signatures)
* [evthehermit/YaraRules](https://github.com/kevthehermit/YaraRules)
* [MalGamy/YARA_Rules](https://github.com/MalGamy/YARA_Rules)
* [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules)
* [securitymagic/yara](https://github.com/securitymagic/yara)
* [telekom-security/malware_analysis](https://github.com/telekom-security/malware_analysis)
* [tenable/yara-rules](https://github.com/tenable/yara-rules)

\* That doesn't mean they will actually detect something; just that they are processed properly by the yara-python

## Screenshots

<div align="center">

![paranoya-screenshot](https://github.com/c0m4r/paranoya/assets/6292788/24641b5d-7541-4bef-acd3-b671b1451767)

</div>

## License

```
paranoya: Simple IOC and YARA Scanner for Linux®
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

Linux® is the registered trademark of Linus Torvalds in the U.S. and other countries.
```

## Funding

If you found this software helpful, please consider [making donation](https://en.wosp.org.pl/fundacja/jak-wspierac-wosp/wesprzyj-online) to a charity on my behalf. Thank you.
