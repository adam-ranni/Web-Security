# Requires BOOKSHOP_SECRET_KEY and BOOKSHOP_JWT_SECRET: different random values, at least 32 characters each.
# Set BOOKSHOP_DATA_DIR to the directory containing the explicitly initialized/migrated shop.sqlite3.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$shopPort = if ($env:BOOKSHOP_PORT) { $env:BOOKSHOP_PORT } else { '5006' }
& "$PSScriptRoot/.venv/Scripts/python.exe" -m flask --app app run --host 127.0.0.1 --port $shopPort
exit $LASTEXITCODE
