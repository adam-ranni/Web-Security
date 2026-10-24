#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "Destructive reset is disabled. Select a new BOOKSHOP_DATA_DIR and run flask --app app init-db locally." >&2
exit 64
