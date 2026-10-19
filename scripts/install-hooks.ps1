# Enable repository git hooks (pre-commit artefact/secret guard, pre-push CI gate).
# PowerShell entry point; runs scripts/install-hooks.sh via Git for Windows bash.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_bash.ps1')
Invoke-DfBash -Script 'install-hooks.sh' -Arguments $args
