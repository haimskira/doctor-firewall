# Populate vendor/ (wheels, npm cache, Trivy DB, base images). The only step that needs internet.
# PowerShell entry point; runs scripts/vendor.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'vendor.sh' -Arguments $args
