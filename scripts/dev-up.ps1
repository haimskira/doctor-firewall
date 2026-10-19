# Build (offline) and start the development stack with the FMC mock (--down to stop).
# PowerShell entry point; runs scripts/dev-up.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'dev-up.sh' -Arguments $args
