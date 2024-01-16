#!/bin/sh

pacman-key --init
pacman-key --populate
echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist
echo 'Server = http://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist
echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist
pacman -Syyu --noconfirm
pacman -S bash gcc git python3 python-devtools python-pip --noconfirm
cd /opt
git clone https://github.com/c0m4r/paranoya.git
cd paranoya
./deploy.sh
./paranoya.py -p ./test
mkdir scan
exit
