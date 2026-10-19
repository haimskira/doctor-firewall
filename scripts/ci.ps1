# Full local CI gate (lint, types, SAST, unit+integration tests, SCA). Use -- --offline for Trivy SCA.
# PowerShell entry point; runs scripts/ci.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'ci.sh' -Arguments $args
