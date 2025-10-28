@echo off
setlocal enabledelayedexpansion

REM -------------------------------------------------
REM  DMJ Root + Intermediate Certificate Importer
REM  Works even when elevated (uses %~dp0 for paths)
REM -------------------------------------------------

:: Re-run as admin if not already
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [!] Elevating... please accept the UAC prompt.
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

:: Folder where this script lives (always ends with backslash)
set "BASEDIR=%~dp0"

:: Candidate filenames (support .cer/.crt)
set "ROOT_CANDIDATES=dmj-one-root-ca-r1.cer dmj-one-root-ca-r1.crt"
set "ICA_CANDIDATES=dmj-one-issuing-ca-r1.crt dmj-one-issuing-ca-r1.cer"

:: Resolve actual files
set "ROOT_CERT="
for %%F in (%ROOT_CANDIDATES%) do (
  if exist "%BASEDIR%%%F" (
    set "ROOT_CERT=%BASEDIR%%%F"
    goto :gotRoot
  )
)
:gotRoot

set "ICA_CERT="
for %%F in (%ICA_CANDIDATES%) do (
  if exist "%BASEDIR%%%F" (
    set "ICA_CERT=%BASEDIR%%%F"
    goto :gotICA
  )
)
:gotICA

echo --------------------------------------------
echo Installing DMJ Certificates from:
echo   %BASEDIR%
echo --------------------------------------------

if defined ROOT_CERT (
  echo [+] Installing Root CA: "%ROOT_CERT%"
  certutil -addstore -enterprise -f "Root" "%ROOT_CERT%"
) else (
  echo [x] Root certificate not found in folder. Looked for:
  echo     %ROOT_CANDIDATES%
)

if defined ICA_CERT (
  echo [+] Installing Intermediate CA: "%ICA_CERT%"
  certutil -addstore -enterprise -f "CA" "%ICA_CERT%"
) else (
  echo [x] Intermediate certificate not found in folder. Looked for:
  echo     %ICA_CANDIDATES%
)

echo --------------------------------------------
echo [✓] Done. Verify with: certmgr.msc
echo   - Trusted Root Certification Authorities
echo   - Intermediate Certification Authorities
echo --------------------------------------------
pause
endlocal