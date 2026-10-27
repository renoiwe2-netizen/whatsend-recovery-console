#!/bin/sh
set -eu
# Fixture only: the gateway is healthy before any browser is started.
if [ "$(id -u)" = 0 ]; then echo 'Run as the unprivileged container user.' >&2; exit 21; fi
exec python3 /opt/poc/server.py
