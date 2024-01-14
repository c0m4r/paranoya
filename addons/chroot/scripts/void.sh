#!/bin/sh

xbps-install -Suy xbps
xbps-install -Suy
xbps-install -Suy bash curl git python3 python3-devel python3-pip openssl-devel gcc wget
xbps-reconfigure -fa
cd /opt
git clone https://github.com/c0m4r/Loki-daemonized.git
cd Loki-daemonized
./deploy.sh
./loki.py -p ./test
mkdir scan
exit
