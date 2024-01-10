#!/usr/bin/env bash

# Colors
ORANGE="\e[1;33m"
ENDCOLOR="\e[0m"

# Color print function
function print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

# Looking for pip
if which pip3 ; then
    PIP_BIN="pip3"
elif which pip ; then
    PIP_BIN="pip"
else
    echo "pip3 or pip not found"
fi

# Looking for python
if which python3 ; then
    PYTHON_BIN="python3"
elif which python ; then
    PYTHON_BIN="python"
else
    echo "python3 or python not found"
fi

if [ ! -e pyvenv.cfg ]; then
    print "Creating venv, this might take a while..."
    $PYTHON_BIN -m venv .
    print 'Entering venv (type: "deactivate" to exit)'
    source bin/activate
    ls -la
    print "Upgrading pip and tools"
    $BIN_PIP install --upgrade pip setuptools wheel || true
    print "Installing pip modules"
    $BIN_PIP install -r requirements.txt
else
    print 'Entering venv (type "deactivate" to exit)'
    source bin/activate
fi
