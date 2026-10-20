# PowerShell entry point; runs scripts/publish-images.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'publish-images.sh' -Arguments $args
