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

echo Running tests...
cargo test --workspace
if errorlevel 1 goto fail

echo Running rustfmt...
cargo fmt --check
if errorlevel 1 goto fail

echo Running clippy...
cargo clippy --all-targets --all-features -- -D warnings
if errorlevel 1 goto fail

echo Running fuzz-lite smoke tests...
cargo run -p aegis-fuzzlite -- --iters 200 --max-len 4096
if errorlevel 1 goto fail

echo Running CLI smoke tests...
if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%"
mkdir "%TMP_DIR%"

set INPUT_FILE=%TMP_DIR%\\input.bin
set META_FILE=%TMP_DIR%\\meta.bin
set PACK_FILE=%TMP_DIR%\\packed.aegis
set UNPACK_FILE=%TMP_DIR%\\unpacked.bin
set KEY_FILE=%TMP_DIR%\\test.key
set KEY_FILE_2=%TMP_DIR%\\test2.key
set KEY_FILE_3=%TMP_DIR%\\test3.key
set KEY_FILE_WRONG=%TMP_DIR%\\wrong.key
set PUB_KEY_FILE=%TMP_DIR%\\recipient.pub
set PRIV_KEY_FILE=%TMP_DIR%\\recipient.priv
set PUB_KEY_FILE_2=%TMP_DIR%\\recipient2.pub
set PRIV_KEY_FILE_2=%TMP_DIR%\\recipient2.priv
set ENC_FILE=%TMP_DIR%\\encrypted.aegis
set DEC_FILE=%TMP_DIR%\\decrypted.bin
set DEC_FILE_2=%TMP_DIR%\\decrypted2.bin
set DEC_FILE_3=%TMP_DIR%\\decrypted3.bin
set DEC_FILE_PUB=%TMP_DIR%\\decrypted_pub.bin
set CORRUPT_FILE=%TMP_DIR%\\corrupt.aegis
set WRONG_DEC_FILE=%TMP_DIR%\\wrong_dec.bin
set WRONG_DEC_TMP=%TMP_DIR%\\wrong_dec.tmp
set PW_ENC_FILE=%TMP_DIR%\\pw_encrypted.aegis
set PW_DEC_FILE=%TMP_DIR%\\pw_decrypted.bin
set ROTATED_FILE=%TMP_DIR%\\rotated.aegis
set PW_WRONG_DEC=%TMP_DIR%\\pw_wrong.bin
set PW_WRONG_TMP=%TMP_DIR%\\pw_wrong.tmp
set PW_MISSING_DEC=%TMP_DIR%\\pw_missing.bin
set PW_MISSING_TMP=%TMP_DIR%\\pw_missing.tmp

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

echo Generating additional recipient keys...
cargo run -p aegis-cli -- keygen "%KEY_FILE_2%" --force
if errorlevel 1 goto fail

cargo run -p aegis-cli -- keygen "%KEY_FILE_3%" --force
if errorlevel 1 goto fail

echo Generating public/private keypairs...
cargo run -p aegis-cli -- keygen --public "%PUB_KEY_FILE%" --private "%PRIV_KEY_FILE%" --force
if errorlevel 1 goto fail

cargo run -p aegis-cli -- keygen --public "%PUB_KEY_FILE_2%" --private "%PRIV_KEY_FILE_2%" --force
if errorlevel 1 goto fail

echo Encrypting payload...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%ENC_FILE%" --recipient-key "%KEY_FILE%" --recipient-key "%KEY_FILE_2%" --recipient-password --recipient-pubkey "%PUB_KEY_FILE%"
if errorlevel 1 goto fail

echo Decrypting payload (recipient 1)...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_FILE%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail

fc /b "%INPUT_FILE%" "%DEC_FILE%" >nul
if errorlevel 1 goto fail

echo Decrypting payload (recipient 2)...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_FILE_2%" --recipient-key "%KEY_FILE_2%"
if errorlevel 1 goto fail

fc /b "%INPUT_FILE%" "%DEC_FILE_2%" >nul
if errorlevel 1 goto fail

echo Decrypting payload (password recipient)...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_FILE_3%" --recipient-password
if errorlevel 1 goto fail

fc /b "%INPUT_FILE%" "%DEC_FILE_3%" >nul
if errorlevel 1 goto fail

echo Decrypting payload (public key recipient)...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_FILE_PUB%" --private-key "%PRIV_KEY_FILE%"
if errorlevel 1 goto fail

fc /b "%INPUT_FILE%" "%DEC_FILE_PUB%" >nul
if errorlevel 1 goto fail

echo Listing recipients...
cargo run -p aegis-cli -- list-recipients "%ENC_FILE%"
if errorlevel 1 goto fail

echo Rotating recipients...
cargo run -p aegis-cli -- rotate "%ENC_FILE%" --output "%ROTATED_FILE%" --auth-key "%KEY_FILE_2%" --add-recipient-key "%KEY_FILE_3%" --add-recipient-pubkey "%PUB_KEY_FILE_2%" --remove-recipient 1
if errorlevel 1 goto fail

echo Verifying removed recipient fails...
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%WRONG_DEC_FILE%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"
if exist "%WRONG_DEC_TMP%" del /q "%WRONG_DEC_TMP%"

echo Verifying new recipient works...
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE%" --recipient-key "%KEY_FILE_3%"
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE%" >nul
if errorlevel 1 goto fail

echo Verifying rotated public key recipient works...
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE_PUB%" --private-key "%PRIV_KEY_FILE_2%"
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE_PUB%" >nul
if errorlevel 1 goto fail

echo Verifying existing recipient works...
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE_2%" --recipient-key "%KEY_FILE_2%"
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE_2%" >nul
if errorlevel 1 goto fail

echo Verifying password recipient works after rotation...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE_3%" --recipient-password
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE_3%" >nul
if errorlevel 1 goto fail

echo Verifying wrong key rejection...
cargo run -p aegis-cli -- keygen "%KEY_FILE_WRONG%" --force
if errorlevel 1 goto fail

cargo run -p aegis-cli -- dec "%ENC_FILE%" "%WRONG_DEC_FILE%" --recipient-key "%KEY_FILE_WRONG%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"
if exist "%WRONG_DEC_TMP%" del /q "%WRONG_DEC_TMP%"

echo Verifying wrong private key rejection...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%WRONG_DEC_FILE%" --private-key "%PRIV_KEY_FILE_2%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"
if exist "%WRONG_DEC_TMP%" del /q "%WRONG_DEC_TMP%"

echo Verifying corrupted ciphertext rejection...
copy /b "%ENC_FILE%" + "%ENC_FILE%" "%CORRUPT_FILE%" >nul
if errorlevel 1 goto fail

cargo run -p aegis-cli -- dec "%CORRUPT_FILE%" "%WRONG_DEC_FILE%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"
if exist "%WRONG_DEC_TMP%" del /q "%WRONG_DEC_TMP%"

echo Testing password-based encryption...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%PW_ENC_FILE%" --recipient-password
if errorlevel 1 goto fail

cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%PW_DEC_FILE%" --recipient-password
if errorlevel 1 goto fail

fc /b "%INPUT_FILE%" "%PW_DEC_FILE%" >nul
if errorlevel 1 goto fail

echo Verifying wrong password rejection...
set AEGIS_PASSWORD=wrong-pass-456
set AEGIS_PASSWORD_CONFIRM=wrong-pass-456
cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%PW_WRONG_DEC%" --recipient-password
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%PW_WRONG_DEC%" del /q "%PW_WRONG_DEC%"
if exist "%PW_WRONG_TMP%" del /q "%PW_WRONG_TMP%"

echo Verifying missing password rejection...
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%PW_MISSING_DEC%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
if exist "%PW_MISSING_DEC%" del /q "%PW_MISSING_DEC%"
if exist "%PW_MISSING_TMP%" del /q "%PW_MISSING_TMP%"

echo Verifying keyfile misuse rejection...
cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%PW_MISSING_DEC%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
if exist "%PW_MISSING_DEC%" del /q "%PW_MISSING_DEC%"
if exist "%PW_MISSING_TMP%" del /q "%PW_MISSING_TMP%"

set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=

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
