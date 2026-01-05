@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..

pushd "%ROOT_DIR%" >nul

set TMP_DIR=%ROOT_DIR%\target\aegis-smoke

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
if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%"
mkdir "%TMP_DIR%"

set INPUT_FILE=%TMP_DIR%\\input.bin
set META_FILE=%TMP_DIR%\\meta.bin
set PACK_FILE=%TMP_DIR%\\packed.aegis
set UNPACK_FILE=%TMP_DIR%\\unpacked.bin
set KEY_FILE=%TMP_DIR%\\test.key
set KEY_FILE_WRONG=%TMP_DIR%\\wrong.key
set ENC_FILE=%TMP_DIR%\\encrypted.aegis
set DEC_FILE=%TMP_DIR%\\decrypted.bin
set CORRUPT_FILE=%TMP_DIR%\\corrupt.aegis
set WRONG_DEC_FILE=%TMP_DIR%\\wrong_dec.bin

echo mock-data> "%INPUT_FILE%"
echo mock-meta> "%META_FILE%"

cargo run -p aegis-cli -- pack "%INPUT_FILE%" "%PACK_FILE%" --metadata "%META_FILE%"
if errorlevel 1 goto fail

cargo run -p aegis-cli -- inspect "%PACK_FILE%"
if errorlevel 1 goto fail

cargo run -p aegis-cli -- unpack "%PACK_FILE%" "%UNPACK_FILE%"
if errorlevel 1 goto fail

if not exist "%UNPACK_FILE%" goto fail
fc /b "%INPUT_FILE%" "%UNPACK_FILE%" >nul
if errorlevel 1 goto fail

echo Generating key file...
cargo run -p aegis-cli -- keygen "%KEY_FILE%" --force
if errorlevel 1 goto fail

echo Encrypting payload...
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%ENC_FILE%" --key "%KEY_FILE%"
if errorlevel 1 goto fail

echo Decrypting payload...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_FILE%" --key "%KEY_FILE%"
if errorlevel 1 goto fail

fc /b "%INPUT_FILE%" "%DEC_FILE%" >nul
if errorlevel 1 goto fail

echo Verifying wrong key rejection...
cargo run -p aegis-cli -- keygen "%KEY_FILE_WRONG%" --force
if errorlevel 1 goto fail

cargo run -p aegis-cli -- dec "%ENC_FILE%" "%WRONG_DEC_FILE%" --key "%KEY_FILE_WRONG%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"

echo Verifying corrupted ciphertext rejection...
copy /b "%ENC_FILE%" + "%ENC_FILE%" "%CORRUPT_FILE%" >nul
if errorlevel 1 goto fail

cargo run -p aegis-cli -- dec "%CORRUPT_FILE%" "%WRONG_DEC_FILE%" --key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"

set CODE=0
goto cleanup

:fail
set CODE=%ERRORLEVEL%

:cleanup
if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%"
popd >nul
if "%CODE%"=="0" (
  echo.
  echo All checks passed.
  exit /b 0
) else (
  echo.
  echo Checks failed with exit code %CODE%.
  exit /b %CODE%
)
