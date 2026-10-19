# Shared helper for the PowerShell entry points: run the matching POSIX script with
# Git for Windows' bash, so Windows and Linux execute exactly the same logic.
function Invoke-DfBash {
    param([Parameter(Mandatory = $true)][string]$Script, [string[]]$Arguments = @())
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe')
    )
    $bash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $bash) {
        throw 'Git for Windows (bash.exe) was not found. Install Git for Windows.'
    }
    $target = Join-Path $PSScriptRoot $Script
    & $bash $target @Arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
