@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..

pushd "%ROOT_DIR%" >nul

echo Checking Rust toolchain...
where cargo >nul 2>&1
if errorlevel 1 (
  echo cargo not found in PATH.
  exit /b 1
)
where rustc >nul 2>&1
if errorlevel 1 (
  echo rustc not found in PATH.
  exit /b 1
)

echo Checking dependencies...
cargo fetch
if errorlevel 1 goto fail

echo Running tests...
cargo test --workspace
if errorlevel 1 goto fail

echo Running rustfmt...
cargo fmt --check
if errorlevel 1 goto fail

echo Running clippy...
cargo clippy --all-targets --all-features -- -D warnings
if errorlevel 1 goto fail

echo Running CLI smoke tests...
set TMP_DIR=%ROOT_DIR%\\target\\aegis-smoke
if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%"
mkdir "%TMP_DIR%"

set INPUT_FILE=%TMP_DIR%\\input.bin
set META_FILE=%TMP_DIR%\\meta.bin
set PACK_FILE=%TMP_DIR%\\packed.aegis
set UNPACK_FILE=%TMP_DIR%\\unpacked.bin

echo mock-data> "%INPUT_FILE%"
echo mock-meta> "%META_FILE%"

cargo run -p aegis-cli -- pack "%INPUT_FILE%" "%PACK_FILE%" --metadata "%META_FILE%"
if errorlevel 1 goto fail

cargo run -p aegis-cli -- inspect "%PACK_FILE%"
if errorlevel 1 goto fail

cargo run -p aegis-cli -- unpack "%PACK_FILE%" "%UNPACK_FILE%"
if errorlevel 1 goto fail

if not exist "%UNPACK_FILE%" goto fail

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
