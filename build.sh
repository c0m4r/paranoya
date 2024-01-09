#!/bin/bash
set -e

ORANGE='\e[1;33m'
ENDCOLOR="\e[0m"

function print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

print "Building Loki for $(arch) 🚀"
print "Build (1/8): venv"
source bin/activate

print "Build (2/8): upgrade tools"
pip3 install pyinstaller black ruff

print "Build (3/8): black"
bin/black ./*.py ./lib/*.py

print "Build (4/8): ruff"
bin/ruff -v ./*.py ./lib/*.py

rm -rf build/
rm -rf dist/

print "Build (5/8): pyinstaller loki.py"
pyinstaller -F \
    --hidden-import lib.lokilogger \
    --hidden-import lib.helpers \
    --paths=lib/site-packages \
    --paths=lib loki.py

print "Build (6/8): pyinstaller upgrader.py"
pyinstaller -F \
    --paths=lib/site-packages \
    --paths=lib upgrader.py

print "Build (7/8): pyinstaller client.py"
pyinstaller -F client.py

print "Build (8/8): packaging"
rm -rf Loki-daemonized-"$(arch)"*
cp -r config dist/
cp -r README.md dist/
cp -r LICENSE dist/
cp -r CHANGELOG dist/
mkdir dist/lib
cp lib/*.py dist/lib/
mv dist Loki-daemonized-"$(arch)"
zip -r -9 -T Loki-daemonized-"$(arch)".zip Loki-daemonized-"$(arch)"
tar -I 'gzip -9' -cvf Loki-daemonized-"$(arch)".tar.gz Loki-daemonized-"$(arch)"
mv Loki-daemonized-"$(arch)" dist
print "Build complete 🎉"
