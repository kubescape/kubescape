@ECHO OFF

IF "%1"=="install" goto Install
IF "%1"=="build" goto Build
IF "%1"=="all" goto All
IF "%1"=="" goto Error ELSE goto Error

:Install

if exist C:\MSYS64\ (
    echo "MSYS2 already installed"
) else (
    mkdir temp_install & cd temp_install

    echo "Downloading MSYS2..."
    curl -L https://github.com/msys2/msys2-installer/releases/download/2022-06-03/msys2-x86_64-20220603.exe > msys2-x86_64-20220603.exe

    echo "Installing MSYS2..."
    msys2-x86_64-20220603.exe install --root C:\MSYS64 --confirm-command

    cd .. && rmdir /s /q temp_install
)


echo "Adding MSYS2 to path..."
SET "PATH=C:\MSYS64\mingw64\bin;C:\MSYS64\usr\bin;%PATH%"
echo %PATH%

echo "Installing MSYS2 packages..."
pacman -S --needed --noconfirm make
pacman -S --needed --noconfirm mingw-w64-x86_64-cmake
pacman -S --needed --noconfirm mingw-w64-x86_64-gcc
pacman -S --needed --noconfirm mingw-w64-x86_64-pkg-config
pacman -S --needed --noconfirm msys2-w32api-runtime

IF "%1"=="all" GOTO Build
GOTO End

:Build
SET "PATH=C:\MSYS2\mingw64\bin;C:\MSYS2\usr\bin;%PATH%"
make libgit2
GOTO End

:All
GOTO Install

:Error
echo "Error: Unknown option"
GOTO End

:End
