# Offline vulnerability scan of lock files and images with the bundled Trivy DB.
# PowerShell entry point; runs scripts/scan-offline.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'scan-offline.sh' -Arguments $args
