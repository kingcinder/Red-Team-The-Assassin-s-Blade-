# ============================================================
# RedTeam Harness shortcut - install (PowerShell / Git Bash)
# Delegates to the lifecycle wrapper redteam.sh via Git Bash.
# Requires Git for Windows: https://git-scm.com/download/win
# Keep this file next to redteam.sh (repo root).
# ============================================================

$wrapper = Join-Path $PSScriptRoot 'redteam.sh'
if (-not (Test-Path -LiteralPath $wrapper)) {
    Write-Error "redteam.sh not found next to this shortcut. Keep this file in the repo root, next to redteam.sh."
    exit 1
}

$bash = (Get-Command bash -ErrorAction SilentlyContinue).Source
if (-not $bash) {
    $candidates = @(
        "$env:ProgramFiles\Git\bin\bash.exe",
        "$env:ProgramFiles\Git\usr\bin\bash.exe",
        "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
        "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { $bash = $p; break }
    }
}
if (-not $bash) {
    Write-Error "bash not found. Install Git for Windows (https://git-scm.com/download/win), then re-open the terminal."
    exit 1
}

& $bash $wrapper 'install' @args
exit $LASTEXITCODE