@echo off
set process1=SignalRgb.exe
set process2=HueSync.exe
set arg=%1

if not "%arg%"=="" (
    if not "%arg%"=="-d" (
        if not "%arg%"=="--debug" (
            goto :end
        )
    )
)

:checkProcesses
tasklist /FI "IMAGENAME eq %process1%" 2>NUL | find /I /N "%process1%">NUL
set process1Running=%ERRORLEVEL%
tasklist /FI "IMAGENAME eq %process2%" 2>NUL | find /I /N "%process2%">NUL
set process2Running=%ERRORLEVEL%

REM
if "%process1Running%"=="0" (
    if "%process2Running%"=="0" (
        pushd "C:\Users\%USERNAME%\Scripts\rgb-scheduler"
        start "" pythonw -m rgb_scheduler.scheduler %arg% >> "C:\Users\%USERNAME%\Scripts\rgb-scheduler\logs\error.log" 2>&1
        popd
        goto :end
    )
)

timeout /t 1 /nobreak >nul
goto checkProcesses

:end
exit