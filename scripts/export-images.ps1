# PowerShell entry point; runs scripts/export-images.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'export-images.sh' -Arguments $args
