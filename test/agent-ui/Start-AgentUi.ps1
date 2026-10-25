$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
    $env:CGO_ENABLED = "0"
    $env:GOPROXY = "off"
    & go run ./internal/tools/agentui @args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
