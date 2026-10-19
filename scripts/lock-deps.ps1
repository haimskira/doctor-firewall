# Re-lock Python (hashed) and npm dependencies. Dev machine only, needs internet.
# PowerShell entry point; runs scripts/lock-deps.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'lock-deps.sh' -Arguments $args
