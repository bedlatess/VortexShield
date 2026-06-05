$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Frontend = Join-Path $Root "frontend"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Virtual environment not found. Run backend setup first."
}

& $Python -m http.server 48922 --bind 127.0.0.1 --directory $Frontend

