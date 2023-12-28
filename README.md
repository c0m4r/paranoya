![loki-daemonized-icon.png](loki-daemonized-icon.png)

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

Derived from https://github.com/Neo23x0/Loki/blob/5b7175882a9b7247714b47347c2f9dccdf38d894/loki.py

Diff: [loki-daemonized.patch](loki-daemonized.patch)

## Usage

```
usage: loki.py [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost] [-t remote-syslog-port] [-a alert-level] [-w warning-level] [-n notice-level] [-d] [--listen-host listen-host]
               [--listen-port listen-port] [--allhds] [--alldrives] [--printall] [--allreasons] [--noprocscan] [--nofilescan] [--vulnchecks] [--nolevcheck] [--scriptanalysis] [--rootkit] [--noindicator]
               [--dontwait] [--intense] [--csv] [--onlyrelevant] [--nolog] [--update] [--debug] [--maxworkingset MAXWORKINGSET] [--syslogtcp] [--logfolder log-folder] [--nopesieve] [--pesieveshellc]
               [--python PYTHON] [--nolisten] [--excludeprocess EXCLUDEPROCESS] [--force] [--version]

Loki - Simple IOC Scanner

options:
  -h, --help            show this help message and exit
  -p path               Path to scan
  -s kilobyte           Maximum file size to check in KB (default 5000 KB)
  -l log-file           Log file
  -r remote-loghost     Remote syslog system
  -t remote-syslog-port
                        Remote syslog port
  -a alert-level        Alert score
  -w warning-level      Warning score
  -n notice-level       Notice score
  -d                    Run as a daemon
  --listen-host listen-host
                        Listen host for daemon mode
  --listen-port listen-port
                        Listen port for daemon mode
  --allhds              Scan all local hard drives (Windows only)
  --alldrives           Scan all drives (including network drives and removable media)
  --printall            Print all files that are scanned
  --allreasons          Print all reasons that caused the score
  --noprocscan          Skip the process scan
  --nofilescan          Skip the file scan
  --vulnchecks          Run the vulnerability checks
  --nolevcheck          Skip the Levenshtein distance check
  --scriptanalysis      Statistical analysis for scripts to detect obfuscated code (beta)
  --rootkit             Skip the rootkit check
  --noindicator         Do not show a progress indicator
  --dontwait            Do not wait on exit
  --intense             Intense scan mode (also scan unknown file types and all extensions)
  --csv                 Write CSV log format to STDOUT (machine processing)
  --onlyrelevant        Only print warnings or alerts
  --nolog               Don't write a local log file
  --update              Update the signatures from the "signature-base" sub repository
  --debug               Debug output
  --maxworkingset MAXWORKINGSET
                        Maximum working set size of processes to scan (in MB, default 100 MB)
  --syslogtcp           Use TCP instead of UDP for syslog logging
  --logfolder log-folder
                        Folder to use for logging when log file is not specified
  --nopesieve           Do not perform pe-sieve scans
  --pesieveshellc       Perform pe-sieve shellcode scan
  --python PYTHON       Override default python path
  --nolisten            Dot not show listening connections
  --excludeprocess EXCLUDEPROCESS
                        Specify an executable name to exclude from scans, can be used multiple times
  --force               Force the scan on a certain folder (even if excluded with hard exclude in LOKI's code
  --version             Shows welcome text and version of loki, then exit
```

---
## Licensed under GPL 3.0
* Loki - Simple IOC Scanner Copyright (c) 2015 Florian Roth
* Loki (daemonized) - Simple IOC and YARA Scanner fork (c) 2023 c0m4r

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
