Write-Host "Installing Kubescape..." -ForegroundColor Cyan

$BASE_DIR = "$env:USERPROFILE\.kubescape"
$KUBESCAPE_EXEC = "kubescape.exe"

# Determine architecture
$arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
    Write-Host "Error: 32-bit systems are not supported" -ForegroundColor Red
    exit 1
}

# Get latest release version from GitHub API
function Get-LatestVersion {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/kubescape/kubescape/releases/latest" -UseBasicParsing
        return $release.tag_name
    } catch {
        Write-Host "Error: Failed to fetch latest release version" -ForegroundColor Red
        exit 1
    }
}

# Parse command line arguments for version
$version = $null
for ($i = 0; $i -lt $args.Count; $i++) {
    if ($args[$i] -eq "-v" -and $i + 1 -lt $args.Count) {
        $version = $args[$i + 1]
    }
}

# Get version (use provided or fetch latest)
if (-not $version) {
    $version = Get-LatestVersion
    Write-Host "Latest version: $version" -ForegroundColor Cyan
}

# Remove 'v' prefix if present for the filename
$versionNum = $version -replace '^v', ''

# Create installation directory if needed
New-Item -Path $BASE_DIR -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null

# Build download URL with new naming pattern: kubescape_{version}_windows_{arch}.exe
$downloadUrl = "https://github.com/kubescape/kubescape/releases/download/$version/kubescape_${versionNum}_windows_${arch}.exe"

Write-Host "Downloading from: $downloadUrl" -ForegroundColor Cyan

$outputPath = Join-Path $BASE_DIR $KUBESCAPE_EXEC

# Download the binary
try {
    $useBitTransfer = $null -ne (Get-Module -Name BitsTransfer -ListAvailable) -and ($PSVersionTable.PSVersion.Major -le 5)
    if ($useBitTransfer) {
        Write-Host "Using BitsTransfer for download..." -ForegroundColor Gray
        Start-BitsTransfer -Source $downloadUrl -Destination $outputPath
    } else {
        $ProgressPreference = 'SilentlyContinue'  # Speeds up Invoke-WebRequest
        Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath -UseBasicParsing
    }
} catch {
    Write-Host "Error: Failed to download kubescape" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Verify download was successful
if (-not (Test-Path $outputPath) -or (Get-Item $outputPath).Length -eq 0) {
    Write-Host "Error: Download failed or file is empty" -ForegroundColor Red
    Remove-Item $outputPath -ErrorAction SilentlyContinue
    exit 1
}

# Update user PATH if needed
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $currentPath.Contains($BASE_DIR)) {
    $confirmation = Read-Host "Add kubescape to user PATH? (y/n)"
    if ($confirmation -eq 'y') {
        $newPath = $currentPath + ";$BASE_DIR"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $env:Path = $env:Path + ";$BASE_DIR"
        Write-Host "Added $BASE_DIR to PATH" -ForegroundColor Green
    }
}

Write-Host "`nFinished Installation." -ForegroundColor Green

# Try to run version command
try {
    & $outputPath version
} catch {
    Write-Host "Installed to: $outputPath" -ForegroundColor Green
}

Write-Host "`nUsage: kubescape scan" -ForegroundColor Magenta
