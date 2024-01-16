#!/usr/bin/env bash
cd /app/bin
python3 paranoya.py --nolog --pidfile /var/run/paranoya.pid "$@"
