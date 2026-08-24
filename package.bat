@echo off
setlocal

set HERE=%~dp0
set VERSION=1.1.0
set STAGE=%HERE%build\stage
set OUT=%HERE%build\ScrambledUpdates-%VERSION%.zip

call "%HERE%build.bat" || exit /b 1

if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%\SKSE\Plugins\ScrambledUpdates" || exit /b 1
copy /y "%HERE%build\ScrambledUpdates.dll" "%STAGE%\SKSE\Plugins\" >nul || exit /b 1
copy /y "%HERE%build\ScrambledUpdates.pdb" "%STAGE%\SKSE\Plugins\" >nul || exit /b 1
copy /y "%HERE%COPYING" "%STAGE%\SKSE\Plugins\ScrambledUpdates\" >nul || exit /b 1
copy /y "%HERE%EXCEPTIONS.md" "%STAGE%\SKSE\Plugins\ScrambledUpdates\" >nul || exit /b 1

if exist "%OUT%" del "%OUT%"
powershell -NoProfile -Command ^
    "Compress-Archive -Path '%STAGE%\*' -DestinationPath '%OUT%' -Force" || exit /b 1

echo.
echo Packaged: %OUT%
endlocal
