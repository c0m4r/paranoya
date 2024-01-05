#!/usr/bin/env bash
cd /app/bin
python3 loki.py --nolog --pidfile /var/run/loki.pid "$@"
