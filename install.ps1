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
$asset = "kubescape_${versionNum}_windows_${arch}.exe"
$releaseUrl = "https://github.com/kubescape/kubescape/releases/download/$version"
$downloadUrl = "$releaseUrl/$asset"

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

# Every release published under this asset naming also publishes a
# checksums.sha256 manifest covering each asset. Verify the download against it
# before the binary is added to PATH or executed below: a successful HTTP 200
# says nothing about the bytes it carried, so without this a tampered release
# asset, a poisoned CDN object, or an on-path attacker is installed and run
# unnoticed.
#
# This binds the binary to the manifest, not to the project's signing identity:
# both are fetched from the same release over the same channel, so it does not
# defend against a compromised release or GitHub account. Use the cosign
# signature or build provenance attestation for that. It does close the case
# where only the binary object is substituted or corrupted in transit.
#
# Fail closed. A missing manifest or a missing entry means something is wrong
# with the release, not that verification can be skipped.
Write-Host "Verifying checksum..." -ForegroundColor Cyan
try {
    $ProgressPreference = 'SilentlyContinue'
    $response = Invoke-WebRequest -Uri "$releaseUrl/checksums.sha256" -UseBasicParsing
    # GitHub serves release assets as application/octet-stream, for which
    # PowerShell 7 hands back a byte[] while Windows PowerShell 5.1 hands back a
    # string. Decode explicitly so the manifest parses on both instead of
    # silently becoming a per-byte array that matches no asset.
    $manifest = if ($response.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($response.Content)
    } else {
        [string]$response.Content
    }
} catch {
    Write-Host "Error: Failed to download the checksum manifest from $releaseUrl/checksums.sha256" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Remove-Item $outputPath -ErrorAction SilentlyContinue
    exit 1
}

# Manifest lines are "<digest>  <asset>"; match the asset exactly so a substring
# such as kubescape_X_windows_amd64.tar.gz cannot satisfy the check.
$expected = $null
foreach ($line in $manifest -split "`n") {
    $parts = $line.Trim() -split '\s+', 2
    if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $asset) {
        $expected = $parts[0].ToLowerInvariant()
        break
    }
}

if (-not $expected) {
    Write-Host "Error: $asset has no entry in the checksum manifest" -ForegroundColor Red
    Remove-Item $outputPath -ErrorAction SilentlyContinue
    exit 1
}

# Get-FileHash returns uppercase, the manifest is lowercase; normalise both
# rather than leaning on -ne being case-insensitive.
$actual = (Get-FileHash -Path $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    Write-Host "Error: checksum mismatch for $asset" -ForegroundColor Red
    Write-Host "  expected: $expected" -ForegroundColor Red
    Write-Host "  actual:   $actual" -ForegroundColor Red
    Remove-Item $outputPath -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "Checksum verified." -ForegroundColor Green

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
