# Defining input params
param (
    [string]$mode = "error"
)

# Function to install MSYS
function Install {
    Write-Host "Starting install..." -ForegroundColor Cyan

    # Check to see if already installed
    if (Test-Path "C:\MSYS64\") {
        Write-Host "MSYS2 already installed" -ForegroundColor Green
    } else {
        # Create a temp directory
        New-Item -Path "$PSScriptRoot\temp_install" -ItemType Directory > $null
        
        # Download MSYS
        Write-Host "Downloading MSYS2..." -ForegroundColor Cyan
        $bitsJobObj = Start-BitsTransfer "https://github.com/msys2/msys2-installer/releases/download/2022-06-03/msys2-x86_64-20220603.exe" -Destination "$PSScriptRoot\temp_install\msys2-x86_64-20220603.exe"
        switch ($bitsJobObj.JobState) {
            "Transferred" {
                Complete-BitsTransfer -BitsJob $bitsJobObj
                break
            }
            "Error" {
                throw "Error downloading"
            }
        }
        Write-Host "MSYS2 download complete" -ForegroundColor Green

        # Install MSYS
        Write-Host "Installing MSYS2..." -ForegroundColor Cyan
        Start-Process -Filepath "$PSScriptRoot\temp_install\msys2-x86_64-20220603.exe" -ArgumentList @("install", "--root", "C:\MSYS64", "--confirm-command") -Wait -NoNewWindow
        Write-Host "MSYS2 install complete" -ForegroundColor Green

        # Set PATH
        $env:Path = "C:\MSYS64\mingw64\bin;C:\MSYS64\usr\bin;" + $env:Path

        # Install MSYS packages
        Write-Host "Installing MSYS2 packages..." -ForegroundColor Cyan
        Start-Process -Filepath "pacman" -ArgumentList @("-S", "--needed", "--noconfirm", "make") -Wait -NoNewWindow
        Start-Process -Filepath "pacman" -ArgumentList @("-S", "--needed", "--noconfirm", "mingw-w64-x86_64-cmake") -Wait -NoNewWindow
        Start-Process -Filepath "pacman" -ArgumentList @("-S", "--needed", "--noconfirm", "mingw-w64-x86_64-gcc") -Wait -NoNewWindow
        Start-Process -Filepath "pacman" -ArgumentList @("-S", "--needed", "--noconfirm", "mingw-w64-x86_64-pkg-config") -Wait -NoNewWindow
        Start-Process -Filepath "pacman" -ArgumentList @("-S", "--needed", "--noconfirm", "msys2-w32api-runtime") -Wait -NoNewWindow
        Write-Host "MSYS2 packages install complete" -ForegroundColor Green
        
        # Remove temp directory
        Remove-Item "$PSScriptRoot\temp_install" -Recurse
    }
    Write-Host "Install complete" -ForegroundColor Green
}

# Function to build libgit2
function Build {
    Write-Host "Starting build..." -ForegroundColor Cyan

    # Set PATH
    $env:Path = "C:\MSYS64\mingw64\bin;C:\MSYS64\usr\bin;" + $env:Path

    # Build
    Start-Process -Filepath "make" -ArgumentList @("libgit2") -Wait -NoNewWindow

    Write-Host "Build complete" -ForegroundColor Green
}

# Check user call mode
if ($mode -eq "all") {
    Install
    Build
} elseif ($mode -eq "install") {
    Install
} elseif ($mode -eq "build") {
    Build
} else {
    Write-Host "Error: -mode should be one of (all|install|build)" -ForegroundColor Red
}