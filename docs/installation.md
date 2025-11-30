# Installation Guide

This guide covers all the ways to install Kubescape on your system.

## Table of Contents

- [Quick Install](#quick-install)
- [Package Managers](#package-managers)
- [Manual Installation](#manual-installation)
- [Verification](#verification)
- [Updating](#updating)
- [Uninstalling](#uninstalling)

---

## Quick Install

### Linux / macOS (Recommended)

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

This script:
- Detects your OS and architecture (x86_64, ARM64/M1/M2)
- Downloads the latest release
- Installs to `~/.kubescape/`
- Adds to your PATH

### Windows (PowerShell)

Requires PowerShell v5.0 or higher:

```powershell
iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex
```

If you get an execution policy error:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Install a Specific Version

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash -s -- -v v3.0.0
```

---

## Package Managers

### Homebrew (macOS/Linux)

```bash
brew install kubescape
```

> **Note**: The [official Homebrew formula](https://formulae.brew.sh/formula/kubescape#default) has git scanning disabled. For full functionality:
> ```bash
> brew tap kubescape/tap
> brew install kubescape-cli
> ```

### Krew (kubectl plugin)

```bash
kubectl krew update
kubectl krew install kubescape

# Use as kubectl plugin
kubectl kubescape scan
```

### Ubuntu / Debian

```bash
sudo add-apt-repository ppa:kubescape/kubescape
sudo apt update
sudo apt install kubescape
```

For other Debian-based or RPM-based distributions, see the [OpenSUSE Build Service](https://software.opensuse.org/download.html?project=home%3Akubescape&package=kubescape).

### Arch Linux

```bash
# Build from source
yay -S kubescape

# Or install pre-built binary (faster)
yay -S kubescape-bin
```

> **Note**: AUR packages are community-supported.

### openSUSE

```bash
sudo zypper refresh
sudo zypper install kubescape
```

> **Note**: Community-supported.

### NixOS / Nix

```bash
# Try in ephemeral shell
nix-shell -p kubescape

# Or add to configuration.nix
environment.systemPackages = with pkgs; [ kubescape ];

# Or with home-manager
home.packages = with pkgs; [ kubescape ];
```

> **Note**: Community-supported. See [NixOS support](https://nixos.wiki/wiki/Support) for issues.

### Snap

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/kubescape)

```bash
sudo snap install kubescape
```

### Chocolatey (Windows)

```powershell
choco install kubescape
```

> **Note**: [Community-supported](https://community.chocolatey.org/packages/kubescape).

### Scoop (Windows)

```powershell
scoop install kubescape
```

> **Note**: [Community-supported](https://scoop.sh/#/apps?q=kubescape).

---

## Manual Installation

### Download from GitHub Releases

1. Go to the [Releases page](https://github.com/kubescape/kubescape/releases)
2. Download the appropriate binary for your OS/architecture
3. Make it executable and move to your PATH:

```bash
# Linux/macOS example
chmod +x kubescape
sudo mv kubescape /usr/local/bin/
```

### Build from Source

```bash
git clone https://github.com/kubescape/kubescape.git
cd kubescape
make build
```

---

## Verification

After installation, verify Kubescape is working:

```bash
# Check version
kubescape version

# Run a simple scan (requires cluster access)
kubescape scan

# Or scan a sample file
kubescape scan https://raw.githubusercontent.com/kubernetes/examples/master/guestbook/all-in-one/guestbook-all-in-one.yaml
```

### Expected Output

```
Kubescape version: vX.X.X
```

---

## Updating

### Script Installation

Re-run the install script to get the latest version:

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

### Package Managers

Use your package manager's update command:

```bash
# Homebrew
brew upgrade kubescape

# apt
sudo apt update && sudo apt upgrade kubescape

# Krew
kubectl krew upgrade kubescape
```

---

## Uninstalling

### Script Installation

```bash
rm -rf ~/.kubescape
# Remove from PATH in your shell config (.bashrc, .zshrc, etc.)
```

### Package Managers

Use your package manager's uninstall command:

```bash
# Homebrew
brew uninstall kubescape

# apt
sudo apt remove kubescape

# Krew
kubectl krew uninstall kubescape
```

---

## Next Steps

- [Getting Started Guide](getting-started.md) - Run your first scan
- [CLI Reference](cli-reference.md) - Full command reference
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
