#!/usr/bin/env sh

# Colors
ORANGE="\e[1;33m"
ENDCOLOR="\e[0m"

# Color print function
print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

# Enter venv function
enter_venv() {
    print "Entering venv via ${SHELL}"
    PATH=$(pwd):$PATH
    /usr/bin/env $SHELL
}

# Looking for python
if which python3 ; then
    PYTHON_BIN="python3"
elif which python ; then
    PYTHON_BIN="python"
else
    echo "python not found"
fi

if [ ! -e pyvenv.cfg ]; then
    print "Creating venv, this might take a while..."
    $PYTHON_BIN -m venv .
    source bin/activate
    print "Upgrading pip and tools"
    $PYTHON_BIN -m pip install --upgrade pip setuptools wheel || true
    print "Installing pip modules"
    $PYTHON_BIN -m pip install -r requirements.txt
    enter_venv
else
    source bin/activate
    enter_venv
fi
