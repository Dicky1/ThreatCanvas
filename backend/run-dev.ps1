# Runs the ThreatCanvas backend using the project's own virtualenv (.venv),
# regardless of whether the venv has been activated in the current shell.
# This avoids accidentally running against a global/system Python whose
# package versions (e.g. starlette) can be incompatible with this project's
# pinned fastapi version.
#
# Usage (from the backend/ folder):
#   .\run-dev.ps1

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Error "Virtualenv not found at $venvPython. Create it first:`n  python -m venv ..\.venv`n  ..\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

Write-Host "Using venv Python: $venvPython" -ForegroundColor Cyan
& $venvPython -m uvicorn app.main:app --reload --port 8000
