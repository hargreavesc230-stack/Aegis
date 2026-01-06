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

echo.
echo Phase 1 - Build and static checks...
cargo fmt --check
if errorlevel 1 goto fail
cargo clippy --all-targets --all-features -- -D warnings
if errorlevel 1 goto fail
cargo test
if errorlevel 1 goto fail

echo Running fuzz-lite smoke tests...
cargo run -p aegis-fuzzlite -- --iters 200 --max-len 4096
if errorlevel 1 goto fail

echo.
echo Phase 2 - Happy-path integration...
if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%"
mkdir "%TMP_DIR%"

set INPUT_FILE=%TMP_DIR%\input.bin
set META_FILE=%TMP_DIR%\meta.bin
set PACK_FILE=%TMP_DIR%\packed.aegis
set UNPACK_FILE=%TMP_DIR%\unpacked.bin
set KEY_FILE=%TMP_DIR%\test.key
set KEY_FILE_2=%TMP_DIR%\test2.key
set KEY_FILE_3=%TMP_DIR%\test3.key
set KEY_FILE_WRONG=%TMP_DIR%\wrong.key
set PUB_KEY_FILE=%TMP_DIR%\recipient.pub
set PRIV_KEY_FILE=%TMP_DIR%\recipient.priv
set PUB_KEY_FILE_2=%TMP_DIR%\recipient2.pub
set PRIV_KEY_FILE_2=%TMP_DIR%\recipient2.priv
set ENC_FILE=%TMP_DIR%\encrypted.aegis
set DEC_FILE=%TMP_DIR%\decrypted.bin
set DEC_FILE_2=%TMP_DIR%\decrypted2.bin
set DEC_FILE_3=%TMP_DIR%\decrypted3.bin
set DEC_FILE_PUB=%TMP_DIR%\decrypted_pub.bin
set WRONG_DEC_FILE=%TMP_DIR%\wrong_dec.bin
set WRONG_DEC_TMP=%TMP_DIR%\wrong_dec.tmp
set PW_ENC_FILE=%TMP_DIR%\pw_encrypted.aegis
set PW_DEC_FILE=%TMP_DIR%\pw_decrypted.bin
set ROTATED_FILE=%TMP_DIR%\rotated.aegis

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

echo Generating key files...
cargo run -p aegis-cli -- keygen "%KEY_FILE%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- keygen "%KEY_FILE_2%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- keygen "%KEY_FILE_3%"
if errorlevel 1 goto fail

echo Generating public/private keypairs...
cargo run -p aegis-cli -- keygen --public "%PUB_KEY_FILE%" --private "%PRIV_KEY_FILE%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- keygen --public "%PUB_KEY_FILE_2%" --private "%PRIV_KEY_FILE_2%"
if errorlevel 1 goto fail

echo Encrypting payload (multi-recipient)...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%ENC_FILE%" --recipient-key "%KEY_FILE%" --recipient-key "%KEY_FILE_2%" --recipient-password --recipient-pubkey "%PUB_KEY_FILE%" --allow-mixed-recipients
if errorlevel 1 goto fail
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=

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
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_FILE_3%" --recipient-password
if errorlevel 1 goto fail
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
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
cargo run -p aegis-cli -- rotate "%ENC_FILE%" --output "%ROTATED_FILE%" --auth-key "%KEY_FILE_2%" --add-recipient-key "%KEY_FILE_3%" --add-recipient-pubkey "%PUB_KEY_FILE_2%" --remove-recipient 1 --allow-mixed-recipients
if errorlevel 1 goto fail

echo Verifying removed recipient fails...
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%WRONG_DEC_FILE%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" del /q "%WRONG_DEC_FILE%"
if exist "%WRONG_DEC_TMP%" del /q "%WRONG_DEC_TMP%"

echo Verifying new recipient works...
if exist "%DEC_FILE%" del /q "%DEC_FILE%"
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE%" --recipient-key "%KEY_FILE_3%"
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE%" >nul
if errorlevel 1 goto fail

echo Verifying rotated public key recipient works...
if exist "%DEC_FILE_PUB%" del /q "%DEC_FILE_PUB%"
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE_PUB%" --private-key "%PRIV_KEY_FILE_2%"
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE_PUB%" >nul
if errorlevel 1 goto fail

echo Verifying existing recipient works...
if exist "%DEC_FILE_2%" del /q "%DEC_FILE_2%"
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE_2%" --recipient-key "%KEY_FILE_2%"
if errorlevel 1 goto fail
fc /b "%INPUT_FILE%" "%DEC_FILE_2%" >nul
if errorlevel 1 goto fail

echo Verifying password recipient works after rotation...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
if exist "%DEC_FILE_3%" del /q "%DEC_FILE_3%"
cargo run -p aegis-cli -- dec "%ROTATED_FILE%" "%DEC_FILE_3%" --recipient-password
if errorlevel 1 goto fail
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
fc /b "%INPUT_FILE%" "%DEC_FILE_3%" >nul
if errorlevel 1 goto fail

echo Testing password-only encryption...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%PW_ENC_FILE%" --recipient-password
if errorlevel 1 goto fail
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=

set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%PW_DEC_FILE%" --recipient-password
if errorlevel 1 goto fail
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
fc /b "%INPUT_FILE%" "%PW_DEC_FILE%" >nul
if errorlevel 1 goto fail

echo.
echo Phase 3 - Misuse and refusal validation...
set SENTINEL_FILE=%TMP_DIR%\sentinel.bin
set PACK_OVERWRITE=%TMP_DIR%\pack_overwrite.aegis
set PACK_OVERWRITE_TMP=%TMP_DIR%\pack_overwrite.tmp
set UNPACK_OVERWRITE=%TMP_DIR%\unpack_overwrite.bin
set UNPACK_OVERWRITE_TMP=%TMP_DIR%\unpack_overwrite.tmp
set ENC_OVERWRITE=%TMP_DIR%\overwrite.aegis
set ENC_OVERWRITE_TMP=%TMP_DIR%\overwrite.tmp
set DEC_OVERWRITE=%TMP_DIR%\overwrite_dec.bin
set DEC_OVERWRITE_TMP=%TMP_DIR%\overwrite_dec.tmp
set MIXED_FAIL=%TMP_DIR%\mixed_fail.aegis
set MIXED_FAIL_TMP=%TMP_DIR%\mixed_fail.tmp
set WRONG_PW_DEC=%TMP_DIR%\pw_wrong.bin
set WRONG_PW_TMP=%TMP_DIR%\pw_wrong.tmp
set WRONG_PRIV_DEC=%TMP_DIR%\priv_wrong.bin
set WRONG_PRIV_TMP=%TMP_DIR%\priv_wrong.tmp
set MISSING_DEC=%TMP_DIR%\missing.bin
set MISSING_TMP=%TMP_DIR%\missing.tmp
set UNSUPPORTED_DEC=%TMP_DIR%\unsupported.bin
set UNSUPPORTED_TMP=%TMP_DIR%\unsupported.tmp

echo existing> "%SENTINEL_FILE%"

echo Verifying pack overwrite refusal...
copy /b "%SENTINEL_FILE%" "%PACK_OVERWRITE%" >nul
cargo run -p aegis-cli -- pack "%INPUT_FILE%" "%PACK_OVERWRITE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
fc /b "%PACK_OVERWRITE%" "%SENTINEL_FILE%" >nul
if errorlevel 1 goto fail
if exist "%PACK_OVERWRITE_TMP%" goto fail

echo Verifying unpack overwrite refusal...
copy /b "%SENTINEL_FILE%" "%UNPACK_OVERWRITE%" >nul
cargo run -p aegis-cli -- unpack "%PACK_FILE%" "%UNPACK_OVERWRITE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
fc /b "%UNPACK_OVERWRITE%" "%SENTINEL_FILE%" >nul
if errorlevel 1 goto fail
if exist "%UNPACK_OVERWRITE_TMP%" goto fail

echo existing> "%SENTINEL_FILE%"
copy /b "%SENTINEL_FILE%" "%ENC_OVERWRITE%" >nul

echo Verifying encrypt overwrite refusal...
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%ENC_OVERWRITE%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
fc /b "%ENC_OVERWRITE%" "%SENTINEL_FILE%" >nul
if errorlevel 1 goto fail
if exist "%ENC_OVERWRITE_TMP%" goto fail

echo Verifying decrypt overwrite refusal...
copy /b "%SENTINEL_FILE%" "%DEC_OVERWRITE%" >nul
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%DEC_OVERWRITE%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
fc /b "%DEC_OVERWRITE%" "%SENTINEL_FILE%" >nul
if errorlevel 1 goto fail
if exist "%DEC_OVERWRITE_TMP%" goto fail

echo Verifying mixed credentials refusal...
set AEGIS_PASSWORD=mock-pass-123
set AEGIS_PASSWORD_CONFIRM=mock-pass-123
cargo run -p aegis-cli -- enc "%INPUT_FILE%" "%MIXED_FAIL%" --recipient-key "%KEY_FILE%" --recipient-password
set CODE=%ERRORLEVEL%
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
if not "%CODE%"=="2" goto fail
if exist "%MIXED_FAIL%" goto fail
if exist "%MIXED_FAIL_TMP%" goto fail

echo Verifying wrong key rejection...
cargo run -p aegis-cli -- keygen "%KEY_FILE_WRONG%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%WRONG_DEC_FILE%" --recipient-key "%KEY_FILE_WRONG%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_DEC_FILE%" goto fail
if exist "%WRONG_DEC_TMP%" goto fail

echo Verifying wrong password rejection...
set AEGIS_PASSWORD=wrong-pass-456
set AEGIS_PASSWORD_CONFIRM=wrong-pass-456
cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%WRONG_PW_DEC%" --recipient-password
set CODE=%ERRORLEVEL%
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
if not "%CODE%"=="5" goto fail
if exist "%WRONG_PW_DEC%" goto fail
if exist "%WRONG_PW_TMP%" goto fail

echo Verifying wrong private key rejection...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%WRONG_PRIV_DEC%" --private-key "%PRIV_KEY_FILE_2%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%WRONG_PRIV_DEC%" goto fail
if exist "%WRONG_PRIV_TMP%" goto fail

echo Verifying missing credentials refusal...
cargo run -p aegis-cli -- dec "%PW_ENC_FILE%" "%MISSING_DEC%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
if exist "%MISSING_DEC%" goto fail
if exist "%MISSING_TMP%" goto fail

echo Verifying unsupported credential combinations refusal...
cargo run -p aegis-cli -- dec "%ENC_FILE%" "%UNSUPPORTED_DEC%" --recipient-key "%KEY_FILE%" --recipient-password
set CODE=%ERRORLEVEL%
if not "%CODE%"=="2" goto fail
if exist "%UNSUPPORTED_DEC%" goto fail
if exist "%UNSUPPORTED_TMP%" goto fail

echo.
echo Phase 4 - Tamper and corruption stress...
set CORRUPT_HEADER=%TMP_DIR%\corrupt_header.aegis
set CORRUPT_RECIP=%TMP_DIR%\corrupt_recipient.aegis
set CORRUPT_CIPHERTEXT=%TMP_DIR%\corrupt_ciphertext.aegis
set TRUNC_HEADER=%TMP_DIR%\trunc_header.aegis
set TRUNC_BODY=%TMP_DIR%\trunc_body.aegis
set TRUNC_TAIL=%TMP_DIR%\trunc_tail.aegis
set TAMPER_OUT=%TMP_DIR%\tamper_out.bin
set TAMPER_TMP=%TMP_DIR%\tamper_out.tmp

powershell -NoProfile -Command "$bytes=[IO.File]::ReadAllBytes('%ENC_FILE%'); $bytes[0]=($bytes[0]-bxor 0xFF); [IO.File]::WriteAllBytes('%CORRUPT_HEADER%',$bytes)"
if errorlevel 1 goto fail

powershell -NoProfile -Command "$bytes=[IO.File]::ReadAllBytes('%ENC_FILE%'); $cursor=36; $cursor+=2+2+4+4+4; $saltLen=[BitConverter]::ToUInt16($bytes,$cursor); $cursor+=2+$saltLen; $nonceLen=[BitConverter]::ToUInt16($bytes,$cursor); $cursor+=2+$nonceLen; $bytes[$cursor]=0; $bytes[$cursor+1]=0; [IO.File]::WriteAllBytes('%CORRUPT_RECIP%',$bytes)"
if errorlevel 1 goto fail

powershell -NoProfile -Command "$bytes=[IO.File]::ReadAllBytes('%ENC_FILE%'); $header=[BitConverter]::ToUInt16($bytes,10); $idx=$header+16; if ($idx -ge $bytes.Length) { $idx=$header }; $bytes[$idx]=($bytes[$idx]-bxor 0xFF); [IO.File]::WriteAllBytes('%CORRUPT_CIPHERTEXT%',$bytes)"
if errorlevel 1 goto fail

powershell -NoProfile -Command "$bytes=[IO.File]::ReadAllBytes('%ENC_FILE%'); $header=[BitConverter]::ToUInt16($bytes,10); [IO.File]::WriteAllBytes('%TRUNC_HEADER%',$bytes[0..($header-2)])"
if errorlevel 1 goto fail

powershell -NoProfile -Command "$bytes=[IO.File]::ReadAllBytes('%ENC_FILE%'); $header=[BitConverter]::ToUInt16($bytes,10); $end=[Math]::Min($bytes.Length-1,$header+8); [IO.File]::WriteAllBytes('%TRUNC_BODY%',$bytes[0..($end-1)])"
if errorlevel 1 goto fail

powershell -NoProfile -Command "$bytes=[IO.File]::ReadAllBytes('%ENC_FILE%'); $end=$bytes.Length-2; [IO.File]::WriteAllBytes('%TRUNC_TAIL%',$bytes[0..$end])"
if errorlevel 1 goto fail

if exist "%TAMPER_OUT%" del /q "%TAMPER_OUT%"
cargo run -p aegis-cli -- dec "%CORRUPT_HEADER%" "%TAMPER_OUT%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="3" goto fail
if exist "%TAMPER_OUT%" goto fail
if exist "%TAMPER_TMP%" goto fail

if exist "%TAMPER_OUT%" del /q "%TAMPER_OUT%"
cargo run -p aegis-cli -- dec "%CORRUPT_RECIP%" "%TAMPER_OUT%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="3" goto fail
if exist "%TAMPER_OUT%" goto fail
if exist "%TAMPER_TMP%" goto fail

if exist "%TAMPER_OUT%" del /q "%TAMPER_OUT%"
cargo run -p aegis-cli -- dec "%CORRUPT_CIPHERTEXT%" "%TAMPER_OUT%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%TAMPER_OUT%" goto fail
if exist "%TAMPER_TMP%" goto fail

if exist "%TAMPER_OUT%" del /q "%TAMPER_OUT%"
cargo run -p aegis-cli -- dec "%TRUNC_HEADER%" "%TAMPER_OUT%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="3" goto fail
if exist "%TAMPER_OUT%" goto fail
if exist "%TAMPER_TMP%" goto fail

if exist "%TAMPER_OUT%" del /q "%TAMPER_OUT%"
cargo run -p aegis-cli -- dec "%TRUNC_BODY%" "%TAMPER_OUT%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%TAMPER_OUT%" goto fail
if exist "%TAMPER_TMP%" goto fail

if exist "%TAMPER_OUT%" del /q "%TAMPER_OUT%"
cargo run -p aegis-cli -- dec "%TRUNC_TAIL%" "%TAMPER_OUT%" --recipient-key "%KEY_FILE%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="5" goto fail
if exist "%TAMPER_OUT%" goto fail
if exist "%TAMPER_TMP%" goto fail

echo.
echo Phase 5 - Stress and bounds...
set EMPTY_FILE=%TMP_DIR%\empty.bin
set EMPTY_ENC=%TMP_DIR%\empty.aegis
set EMPTY_DEC=%TMP_DIR%\empty.dec
set SMALL_FILE=%TMP_DIR%\small.bin
set SMALL_ENC=%TMP_DIR%\small.aegis
set SMALL_DEC=%TMP_DIR%\small.dec
set LARGE_FILE=%TMP_DIR%\large.bin
set LARGE_ENC=%TMP_DIR%\large.aegis
set LARGE_DEC=%TMP_DIR%\large.dec

type nul > "%EMPTY_FILE%"
<nul set /p="A" > "%SMALL_FILE%"
fsutil file createnew "%LARGE_FILE%" 1048576 >nul
if errorlevel 1 goto fail

cargo run -p aegis-cli -- enc "%EMPTY_FILE%" "%EMPTY_ENC%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- dec "%EMPTY_ENC%" "%EMPTY_DEC%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail
fc /b "%EMPTY_FILE%" "%EMPTY_DEC%" >nul
if errorlevel 1 goto fail

cargo run -p aegis-cli -- enc "%SMALL_FILE%" "%SMALL_ENC%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- dec "%SMALL_ENC%" "%SMALL_DEC%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail
fc /b "%SMALL_FILE%" "%SMALL_DEC%" >nul
if errorlevel 1 goto fail

cargo run -p aegis-cli -- enc "%LARGE_FILE%" "%LARGE_ENC%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail
cargo run -p aegis-cli -- dec "%LARGE_ENC%" "%LARGE_DEC%" --recipient-key "%KEY_FILE%"
if errorlevel 1 goto fail
fc /b "%LARGE_FILE%" "%LARGE_DEC%" >nul
if errorlevel 1 goto fail

echo.
echo Phase 6 - Cleanup verification...
dir /b "%TMP_DIR%\*.tmp" 2>nul | findstr . >nul
if not errorlevel 1 goto fail

set CODE=0
goto cleanup

:fail
set CODE=%ERRORLEVEL%

:cleanup
set AEGIS_PASSWORD=
set AEGIS_PASSWORD_CONFIRM=
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
