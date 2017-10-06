@echo off
setlocal ENABLEDELAYEDEXPANSION
pushd %~dp0

set appname=pacdbger
set switches=/MD /Os
set libs=Ole32.lib OleAut32.lib version.lib bufferoverflowU.lib
set arch=
for /f "usebackq delims=" %%i in (`"cl.exe 2>&1"`) do (
    if "!arch!"=="" (
        set arch=%%i
        set arch=!arch:~-2!
    )
)

cl.exe %switches% /Fe%appname%_x%arch%.exe %appname%.c %libs%

popd
