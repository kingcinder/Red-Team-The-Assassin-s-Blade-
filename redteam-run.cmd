@echo off
rem ============================================================
rem RedTeam Harness shortcut - run (cmd.exe / Git Bash)
rem Delegates to the lifecycle wrapper redteam.sh via Git Bash.
rem Requires Git for Windows: https://git-scm.com/download/win
rem Keep this file next to redteam.sh (repo root).
rem ============================================================
setlocal
if not exist "%~dp0redteam.sh" (
    echo [ERROR] redteam.sh not found next to this shortcut.
    echo         Keep this file in the repo root, next to redteam.sh.
    exit /b 1
)
where bash >nul 2>nul
if errorlevel 1 (
    echo [ERROR] bash not found on PATH. Install Git for Windows:
    echo         https://git-scm.com/download/win
    echo         then close and re-open this terminal.
    exit /b 1
)
bash "%~dp0redteam.sh" run %*
exit /b %errorlevel%