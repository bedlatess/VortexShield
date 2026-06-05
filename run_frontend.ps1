$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$DemoRoot = $Root

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Virtual environment not found. Run backend setup first."
}

& $Python -m http.server 48923 --bind 127.0.0.1 --directory $DemoRoot
