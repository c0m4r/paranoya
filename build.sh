#!/bin/bash
set -e

source bin/activate
pip3 install pyinstaller black ruff
bin/black *.py lib/*.py
bin/ruff *.py lib/*.py
pyinstaller -F --hidden-import lib.lokilogger --hidden-import lib.helpers --hidden-import rfc5424logging --paths=lib/site-packages --paths=lib loki.py
pyinstaller -F --hidden-import lib.lokilogger --hidden-import lib.helpers --hidden-import rfc5424logging --paths=lib/site-packages --paths=lib loki-upgrader.py
rm -rf Loki-daemonized-$(arch)*
cp -r config dist/
cp -r README.md dist/
cp -r LICENSE dist/
cp -r CHANGELOG dist/
mv dist Loki-daemonized-$(arch)
zip -r -9 -T Loki-daemonized-$(arch).zip Loki-daemonized-$(arch)
GZIP=-9 tar cvzf Loki-daemonized-$(arch).tar.gz Loki-daemonized-aarch64
