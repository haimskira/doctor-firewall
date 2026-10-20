# Dev helper: format, lint and type-check the backend and the FMC mock inside the CI test image.
# PowerShell entry point; runs scripts/lint-local.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'lint-local.sh' -Arguments $args
