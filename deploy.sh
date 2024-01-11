#!/usr/bin/env bash
set -e

###########################################################################
#                                                                         #
# Loki (daemonized) deployment script                                     #
# https://github.com/c0m4r/Loki-daemonized                                #
#                                                                         #
# Loki (daemonized): Simple IOC and YARA Scanner                          #
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
        echo "Python not found"
    fi
}

# Color print function
print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
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

if [ ! -e venv/pyvenv.cfg ]; then
    deploy
elif [ "$1" == "--force" ]; then
    deploy
else
    print "Already installed, use --force to recreate venv."
fi
