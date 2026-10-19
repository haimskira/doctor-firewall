# Create infra/secrets/* once with random values (--dev adds the FMC mock password).
# PowerShell entry point; runs scripts/init-secrets.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'init-secrets.sh' -Arguments $args
