#!/bin/sh

apk update
apk add bash gcc git linux-headers musl-dev openssl-dev python3 python3-dev py3-pip
apk add shadow
usermod -s /bin/bash root
cd opt
git clone https://github.com/c0m4r/paranoya.git
cd paranoya
./deploy.sh
./paranoya.py -p ./test
mkdir scan
exit
