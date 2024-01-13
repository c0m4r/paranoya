#!/bin/bash
set -e

VENV_PATH=".tmp_venv"

# https://github.com/flatpak/flatpak-builder-tools
FPG="https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/de56f4702638739f930f4afa648686f12ac4d724/pip/flatpak-pip-generator"
SHA256="545b3e3d7ba0aaa90051f6781b2603795accd88fcec059177dba34a20a6b73c2 flatpak-pip-generator"

if [[ ! -e flatpak-pip-generator ]]; then
    curl -s -o flatpak-pip-generator ${FPG}
    echo ${SHA256} | sha256sum -c || rm flatpak-pip-generator
    chmod +x flatpak-pip-generator
fi

python -m venv "${VENV_PATH}"
source "${VENV_PATH}"/bin/activate
pip install requirements-parser
./flatpak-pip-generator -r ../../requirements.txt
rm -r ${VENV_PATH}
