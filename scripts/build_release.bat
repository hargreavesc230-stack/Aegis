@echo off
setlocal enabledelayedexpansion

rem Prereqs: Rust toolchain in PATH, rustup for multi-target builds, and PowerShell for hashing.

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..
set DIST_DIR=%ROOT_DIR%\dist
set BUNDLE_DIR=%DIST_DIR%\bundle

pushd "%ROOT_DIR%" >nul

where cargo >nul 2>&1
if errorlevel 1 (
  echo cargo not found in PATH.
  exit /b 1
)

where rustup >nul 2>&1
if errorlevel 1 (
  echo rustup not found in PATH.
  exit /b 1
)

echo Cleaning prior outputs...
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
cargo clean
if errorlevel 1 goto fail

echo Building release binaries for all installed targets...
mkdir "%BUNDLE_DIR%"

for /f "delims=" %%A in ('rustup target list --installed') do (
  call :build_target "%%A"
  if errorlevel 1 goto fail
)

echo Cleaning build artifacts...
cargo clean
if errorlevel 1 goto fail

echo.
echo Release artifacts written to %BUNDLE_DIR%
set CODE=0
goto cleanup

:build_target
set TARGET=%~1
set OUT_DIR=%DIST_DIR%\%TARGET%
set BIN_DIR=target\%TARGET%\release
set EXT=
echo %TARGET% | findstr /I "windows" >nul
if not errorlevel 1 set EXT=.exe

echo Building for %TARGET%...
cargo build --release --locked --target %TARGET% -p aegis-cli -p aegis-fuzzlite
if errorlevel 1 exit /b 1

mkdir "%OUT_DIR%"
copy /y "%BIN_DIR%\aegis-cli%EXT%" "%OUT_DIR%\aegis-cli-%TARGET%%EXT%" >nul
if errorlevel 1 exit /b 1
copy /y "%BIN_DIR%\aegis-fuzzlite%EXT%" "%OUT_DIR%\aegis-fuzzlite-%TARGET%%EXT%" >nul
if errorlevel 1 exit /b 1

call :hash "%OUT_DIR%\aegis-cli-%TARGET%%EXT%"
if errorlevel 1 exit /b 1
call :hash "%OUT_DIR%\aegis-fuzzlite-%TARGET%%EXT%"
if errorlevel 1 exit /b 1

move /y "%OUT_DIR%\aegis-cli-%TARGET%%EXT%" "%BUNDLE_DIR%\" >nul
if errorlevel 1 exit /b 1
move /y "%OUT_DIR%\aegis-cli-%TARGET%%EXT%.sha256" "%BUNDLE_DIR%\" >nul
if errorlevel 1 exit /b 1
move /y "%OUT_DIR%\aegis-fuzzlite-%TARGET%%EXT%" "%BUNDLE_DIR%\" >nul
if errorlevel 1 exit /b 1
move /y "%OUT_DIR%\aegis-fuzzlite-%TARGET%%EXT%.sha256" "%BUNDLE_DIR%\" >nul
if errorlevel 1 exit /b 1

rmdir "%OUT_DIR%" >nul 2>&1
exit /b 0

:hash
powershell -NoProfile -Command "$hash=(Get-FileHash -Algorithm SHA256 '%~1').Hash.ToLower(); $name=[IO.Path]::GetFileName('%~1'); \"$hash  $name\" | Out-File -Encoding ascii '%~1.sha256'"
exit /b %ERRORLEVEL%

:fail
set CODE=%ERRORLEVEL%

:cleanup
popd >nul
exit /b %CODE%
