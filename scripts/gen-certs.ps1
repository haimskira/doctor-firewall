# Generate TLS material: --dev (dev CA, UI, FMC mock) or --ui <hostname> (self-signed UI cert).
# PowerShell entry point; runs scripts/gen-certs.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'gen-certs.sh' -Arguments $args
