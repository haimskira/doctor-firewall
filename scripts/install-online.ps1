# PowerShell entry point; runs scripts/install-online.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'install-online.sh' -Arguments $args
