@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..

pushd "%ROOT_DIR%" >nul

echo Running tests...
cargo test --workspace
if errorlevel 1 goto fail

echo Running rustfmt...
cargo fmt --check
if errorlevel 1 goto fail

echo Running clippy...
cargo clippy --all-targets --all-features -- -D warnings
if errorlevel 1 goto fail

echo.
echo All checks passed.
popd >nul
exit /b 0

:fail
set CODE=%ERRORLEVEL%
popd >nul
echo.
echo Checks failed with exit code %CODE%.
exit /b %CODE%
