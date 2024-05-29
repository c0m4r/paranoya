#!/usr/bin/env bash
set -e

###########################################################################
#                                                                         #
# paranoya deployment script                                              #
# https://github.com/c0m4r/paranoya                                       #
#                                                                         #
# paranoya: Simple IOC and YARA Scanner for Linux®                        #
# Copyright (c) 2015-2023 Florian Roth                                    #
# Copyright (c) 2023-2024 c0m4r                                           #
#                                                                         #
# This program is free software: you can redistribute it and/or modify    #
# it under the terms of the GNU General Public License as published by    #
# the Free Software Foundation, either version 3 of the License, or       #
# (at your option) any later version.                                     #
#                                                                         #
# This program is distributed in the hope that it will be useful,         #
# but WITHOUT ANY WARRANTY; without even the implied warranty of          #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
# GNU General Public License for more details.                            #
#                                                                         #
# You should have received a copy of the GNU General Public License       #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                         #
# Linux® is the registered trademark of Linus Torvalds                    #
# in the U.S. and other countries.                                        #
#                                                                         #
###########################################################################

# Colors
ORANGE="\e[1;33m"
ENDCOLOR="\e[0m"

# Python finder function
find_python() {
    if command -v python3 &>/dev/null ; then
        PYTHON_BIN="python3"
    elif command -v python &>/dev/null ; then
        PYTHON_BIN="python"
    elif which python3 &>/dev/null ; then
        PYTHON_BIN="python3"
    elif which python &>/dev/null ; then
        PYTHON_BIN="python"
    else
        print "Error: (python|python3) not found in the expected location"
        BIN_P=$(find /usr/bin -regextype egrep \
            -regex "^/usr/bin/python(3\.|3)[0-9]{1,2}$" | head -n 1)
        LOCAL_P=$(find /usr/local/bin -regextype egrep \
            -regex "^/usr/local/bin/python(3\.|3)[0-9]{1,2}$" | head -n 1)
        if [[ "$BIN_P" ]]; then
            echo "Hint: ln -s $BIN_P /usr/bin/python"
            exit 1
        elif [[ "$LOCAL_P" ]]; then
            echo "Hint: ln -s $LOCAL_P /usr/local/bin/python"
            exit 1
        else
            echo "Giving up. Make sure it's installed within your PATH."
            exit 1
        fi
    fi
}

# Color print function
print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

# Trap function
hint_deps() {
    if [[ $? -gt 0 ]] && [[ "${PYTHON_BIN}" ]]; then
        print "Something went wrong"
        echo "Make sure you have all the dependencies installed:"

        if [[ -e /etc/alpine-release ]] || [[ -e /etc/apk/repositories ]]; then
            echo "# apk add bash gcc git linux-headers musl-dev openssl-dev python3 python3-dev py3-pip"
        elif [[ -e /etc/arch-release ]] || command -v pacman ; then
            echo "# pacman -S bash gcc git python3 python-devtools python-pip"
        elif command -v xbps-install ; then
            echo "# xbps-install -Sy bash gcc git openssl-devel python3 python3-devel"
        elif [[ -e /etc/debian_version ]] || command -v apt-get ; then
            echo "# apt -y install gcc git libssl-dev python3 python3-dev python3-venv"
            echo "# update-alternatives --install /usr/bin/python python /usr/bin/python3 1"
        elif [[ -e /etc/yum/repos.d ]]; then
            echo "# dnf install bash gcc git openssl-devel python3 python3-devel python3-pip"
        else
            echo "- python3 + pip + venv + dev package"
            echo "- gcc + libssl or openssl dev package"
            echo "- kernel headers"
        fi
    fi
}

# Deploy function
deploy() {
    find_python
    print "Creating venv, this might take a while..."
    $PYTHON_BIN -m venv venv
    . venv/bin/activate
    print "Upgrading pip and tools"
    $PYTHON_BIN -m pip install --upgrade pip setuptools wheel || true
    print "Installing pip modules"
    $PYTHON_BIN -m pip install -r requirements.txt
}

trap hint_deps EXIT

if [ ! -e venv/pyvenv.cfg ]; then
    deploy
elif [ "$1" == "--force" ]; then
    deploy
else
    print "Already installed, use --force to recreate venv."
fi
