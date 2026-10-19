# End-to-end smoke test of the running dev stack over verified HTTPS.
# PowerShell entry point; runs scripts/smoke-test.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'smoke-test.sh' -Arguments $args
