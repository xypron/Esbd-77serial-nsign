@echo off
if not exist "build" (
    mkdir build
)

cd build
cmake -G"MinGW Makefiles" ../
mingw32-make
cd ..\
if exist .\build\src\nsign.exe (
    echo "copy nsign.exe"
    copy .\build\src\nsign.exe .
) else (
    echo "build nsign error, nsign.exe not exist!"
)