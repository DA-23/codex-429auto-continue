$scriptPath = Join-Path $PSScriptRoot "codex_429_watcher.py"

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python $scriptPath @args
    exit $LASTEXITCODE
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $scriptPath @args
    exit $LASTEXITCODE
}

Write-Error "python executable not found"
exit 1
