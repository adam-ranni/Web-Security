#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec .venv/bin/python -m flask --app app run --host 127.0.0.1 --port "${BOOKSHOP_PORT:-5006}"
