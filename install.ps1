Write-Host "Installing Kubescape..." -ForegroundColor Cyan

$BASE_DIR=$env:USERPROFILE + "\.kubescape"
$packageName = "/kubescape-windows-latest"

# Get latest release url
$config = Invoke-WebRequest "https://api.github.com/repos/kubescape/kubescape/releases/latest" | ConvertFrom-Json
$url = $config.html_url.Replace("/tag/","/download/")
$fullUrl = $url + $packageName

# Create a new directory if needed
New-Item -Path $BASE_DIR -ItemType "directory" -ErrorAction SilentlyContinue

# Download the binary
$useBitTransfer = $null -ne (Get-Module -Name BitsTransfer -ListAvailable) -and ($PSVersionTable.PSVersion.Major -le 5)
if ($useBitTransfer)
    {
        Write-Information -MessageData 'Using a fallback BitTransfer method since you are running Windows PowerShell'
        Start-BitsTransfer -Source $fullUrl -Destination $BASE_DIR\kubescape.exe
        
    }
    else
    {
       Invoke-WebRequest -Uri $fullUrl -OutFile $BASE_DIR\kubescape.exe
    }

# Update user PATH if needed
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $currentPath.Contains($BASE_DIR)) {
    $confirmation = Read-Host "Add kubescape to user path? (y/n)"
    if ($confirmation -eq 'y') {
        [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$BASE_DIR;", "User")
    }
}

Write-Host "Finished Installation" -ForegroundColor Green 
