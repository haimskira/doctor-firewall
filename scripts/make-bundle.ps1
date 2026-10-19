# Build the offline production bundle: make-bundle <x.y.z> [--skip-ci] [--allow-dirty].
# PowerShell entry point; runs scripts/make-bundle.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'make-bundle.sh' -Arguments $args
