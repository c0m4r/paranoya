#!/bin/bash

source bin/activate
pip3 install pyinstaller
pyinstaller -F --hidden-import lib.lokilogger --hidden-import lib.helpers --hidden-import rfc5424logging --paths=lib/site-packages --paths=lib loki.py
pyinstaller -F --hidden-import lib.lokilogger --hidden-import lib.helpers --hidden-import rfc5424logging --paths=lib/site-packages --paths=lib loki-upgrader.py
