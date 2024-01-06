#!/bin/bash

python -m venv .
source bin/activate
pip3 install install --upgrade pip setuptools wheel
pip3 install -r requirements.txt
