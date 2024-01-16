#!/bin/bash
set -e

###########################################################################
#                                                                         #
# paranoya: build script                                                  #
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

# Color print function
print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

# Parse args
while [[ $# -gt 0 ]]; do
case $1 in
    --with-signatures)
        WITH_SIGNATURES="$1"
        shift
        ;;
    --with-addons)
        WITH_ADDONS="$1"
        shift
        ;;
    --with-source)
        WITH_SOURCE="$1"
        shift
        ;;
    --with-test)
        WITH_TEST="$1"
        shift
        ;;
    -h|--help)
        print "paranoya: build script"
        echo "https://github.com/c0m4r/paranoya"
        echo ""
        echo "Usage: ./build.sh [options]"
        echo ""
        echo "--with-addons        Include addons"
        echo "--with-signatures    Include signature-base"
        echo "--with-source        Include source .py files"
        echo "--with-test          Include test samples"
        exit 0
        ;;
    -*|--*)
        echo "Unknown option: $1"
        exit 1
        ;;
    *)
        continue
        ;;
    esac
done

# Check version
VERSION=$(
    grep ^__version lib/paranoya_logger.py \
    | grep -oP "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
)

# Detect musl
if [[ -e /lib/ld-musl-aarch64.so.1 ]]; then
    VERSION="${VERSION}-musl"
fi

# Build
print "paranoya: build script"
echo "https://github.com/c0m4r/paranoya"
echo "Copyright (c) 2014-2023 Florian Roth"
echo "Copyright (c) 2023-2024 c0m4r"
echo "GNU General Public License v3.0"
print "Building paranoya"
echo "${VERSION}-$(arch) 🚀"

print "Build (1/8): venv"
if [[ ! -e venv/pyvenv.cfg ]]; then
    ./deploy.sh
fi

source venv/bin/activate

print "Build (2/8): upgrade tools"
pip install pyinstaller black ruff

print "Build (3/8): formatting"
black --quiet ./*.py ./lib/*.py

print "Build (4/8): linting"
ruff -v ./*.py ./lib/*.py

rm -rf build/
rm -rf dist/

# Disable venv_check
sed -i \
    -e 's/^venv_check/\#venv_check/g;' \
    -e 's/^from\ lib.venv/\#from\ lib.venv/g;' \
    ./*.py lib/*.py

# PyInstaller
print "Build (5/8): pyinstaller paranoya"
pyinstaller -F paranoya.py

print "Build (6/8): pyinstaller upgrader"
pyinstaller -F upgrader.py

print "Build (7/8): pyinstaller client"
pyinstaller -F client.py

# Enable venv_check back
sed -i \
    -e 's/^\#\ venv_check/venv_check/g;' \
    -e 's/^\#venv_check/venv_check/g;' \
    -e 's/^\#\ from\ lib.venv/from\ lib.venv/g;' \
    -e 's/^\#from\ lib.venv/from\ lib.venv/g;' \
    ./*.py lib/*.py

# Create packages
print "Build (8/8): packaging"

rm -rf paranoya*"$(arch)"*
cp -r config dist/
cp README.md dist/
cp LICENSE dist/
cp CHANGELOG dist/

# Include addons
if [[ "${WITH_ADDONS}" && -d addons ]]; then
    cp -r addons dist/
    rm -rf dist/addons/img
fi

# Include signature-base
if [[ "${WITH_SIGNATURES}" && -d signature-base ]]; then
    cp -r signature-base dist/
fi

# Include source files
if [[ "${WITH_SOURCE}" ]]; then
    cp ./*.py dist/
    mkdir dist/lib
    cp lib/*.py dist/lib/
    cp venv.sh dist/
    cp build.sh dist/
    cp requirements.txt dist/
fi

# Include test samples
if [[ "${WITH_TEST}" ]]; then
    cp -r test dist/
fi

mv dist paranoya-"${VERSION}"-"$(arch)"
if command -v zip &>/dev/null ; then
    zip -r -9 -T paranoya-"${VERSION}"-"$(arch)".zip paranoya-"${VERSION}"-"$(arch)"
fi
if command -v tar &>/dev/null && command -v gzip &>/dev/null ; then
    tar -I "gzip -9" -cvf paranoya-"${VERSION}"-"$(arch)".tar.gz paranoya-"${VERSION}"-"$(arch)"
fi
mv paranoya-"${VERSION}"-"$(arch)" dist

print "Build complete 🎉"
