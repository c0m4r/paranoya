#!/bin/bash
set -e

VENV_PATH=".tmp_venv"
REQ_FILE=".tmp_requirements.txt"

# https://github.com/flatpak/flatpak-builder-tools
FPG="https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/de56f4702638739f930f4afa648686f12ac4d724/pip/flatpak-pip-generator"
SHA256="545b3e3d7ba0aaa90051f6781b2603795accd88fcec059177dba34a20a6b73c2 flatpak-pip-generator"

if [[ ! -e flatpak-pip-generator ]]; then
    curl -s -o flatpak-pip-generator ${FPG}
    echo ${SHA256} | sha256sum -c || rm flatpak-pip-generator
    chmod +x flatpak-pip-generator
fi

# Pinned runtime dependencies from uv.lock
uv export --locked --no-dev --no-hashes --no-header --no-annotate \
    --project ../.. --format requirements-txt -o "${REQ_FILE}"

python -m venv "${VENV_PATH}"
source "${VENV_PATH}"/bin/activate
pip install --uploaded-prior-to=P14D requirements-parser
./flatpak-pip-generator -r "${REQ_FILE}"
rm -r ${VENV_PATH} "${REQ_FILE}"
