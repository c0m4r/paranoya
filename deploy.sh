#!/usr/bin/env bash
set -e

###########################################################################
#                                                                         #
# paranoya deployment script                                              #
# https://github.com/c0m4r/paranoya                                       #
#                                                                         #
# paranoya: Simple IOC and YARA Scanner for Linux®                        #
# Copyright (c) 2015-2023 Florian Roth                                    #
# Copyright (c) 2023-2026 c0m4r                                           #
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

# Version compare function, true if $1 >= $2
version_ge() {
    local -a a b
    local i x y
    IFS=. read -ra a <<< "$1"
    IFS=. read -ra b <<< "$2"
    for i in 0 1 2; do
        x=${a[i]%%[^0-9]*}
        y=${b[i]%%[^0-9]*}
        (( ${x:-0} > ${y:-0} )) && return 0
        (( ${x:-0} < ${y:-0} )) && return 1
    done
    return 0
}

# uv finder function
# Uses uv from PATH if recent enough, otherwise installs the hash-pinned
# uv from requirements-uv.txt into .uv/ with pip (wheels only)
find_uv() {
    local required pinned version
    required=$(sed -n 's/^required-version = ">=\([0-9.]*\)".*/\1/p' pyproject.toml)
    pinned=$(sed -n 's/^uv==\([0-9.]*\).*/\1/p' requirements-uv.txt)

    if command -v uv &>/dev/null ; then
        version=$(uv --version | awk '{print $2}')
        if version_ge "$version" "$required"; then
            UV_BIN="uv"
            return
        fi
        print "uv ${version} found, but >= ${required} is required"
    fi

    if [[ -x .uv/bin/uv ]] && [[ $(.uv/bin/uv --version | awk '{print $2}') == "$pinned" ]]; then
        UV_BIN=".uv/bin/uv"
        return
    fi

    print "Installing uv ${pinned} into .uv (hash-pinned)"
    rm -rf .uv
    $PYTHON_BIN -m venv .uv
    .uv/bin/python -m pip install --disable-pip-version-check --no-deps \
        --only-binary :all: --require-hashes -r requirements-uv.txt
    UV_BIN=".uv/bin/uv"
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
# Installs exactly what uv.lock pins (hash-verified), see [tool.uv] in pyproject.toml
deploy() {
    find_python
    find_uv
    print "Syncing .venv from uv.lock, this might take a while..."
    "$UV_BIN" sync --locked --python "$(command -v $PYTHON_BIN)" "$@"
}

trap hint_deps EXIT

if [ ! -e .venv/pyvenv.cfg ]; then
    deploy
elif [ "$1" == "--force" ]; then
    deploy --reinstall
else
    print "Already installed, use --force to reinstall .venv."
fi
