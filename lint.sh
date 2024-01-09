#!/bin/bash
set -e

ORANGE='\e[1;33m'
ENDCOLOR="\e[0m"

function print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

if [ ! "$1" ]; then
    echo "missing file name"
    exit 0
fi

print "bandit"
bin/bandit $1
print "black"
bin/black $1
print "codespell"
bin/codespell $1
print "mypy"
bin/mypy --install-types --strict $1
print "pylama (ignored: C901)"
bin/pylama --ignore C901 $1
bin/pylama $1 || true
print "pylint(disabled: W0718)"
bin/pylint --disable W0718 $1
print "pyright"
bin/pyright $1
print "ruff"
bin/ruff $1
