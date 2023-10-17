# Installation
## Manually
> **Note**: We do not recommend this method if you want to get auto-updating from package managers or have more platforms supported.
### X86_64 or ARM64 (M1/M2) Linux / macOS
```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

To install a previous version, you can specify it in the command line.

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash -s -- -v v2.3.6
```

### X86_64 Windows
You must have PowerShell v5.0 or higher:
```powershell
iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex
```

If you get an error, you may need to change the execution policy:
```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

## openSUSE
> **Note**: openSUSE community-supported.

```bash
sudo zypper refresh
sudo zypper install kubescape
```

## Arch
```bash
yay -S kubescape
```
If you would like to save some time and do not want to compile, install `kubescape-bin` instead:
> **Note**: kubescape-bin is AUR community-supported.
```bash
yay -S kubescape-bin
```

## Ubuntu
```bash
sudo add-apt-repository ppa:kubescape/kubescape
sudo apt update
sudo apt install kubescape
```

## Other Debian-based or RPM-based Linux Distros
Please follow the [guidelines here](https://software.opensuse.org/download.html?project=home%3Akubescape&package=kubescape).

## Homebrew
> **Note**: The kubescape delivered by [official Homebrew](https://formulae.brew.sh/formula/kubescape#default) comes with git disabled.

```bash
brew install kubescape
```

If you want to have the git enabled one, you can install via the [homebrew-tap](https://github.com/kubescape/homebrew-tap):
```bash
brew tap kubescape/tap
brew install kubescape-cli
```

## Chocolatey
> **Note**: Chocolatey [community-supported](https://community.chocolatey.org/packages/kubescape).
```powershell
choco install kubescape
```

## Scoop
> **Note**: Scoop [community-supported](https://scoop.sh/#/apps?q=kubescape&s=0&d=1&o=true&id=1f5ae05eaafe3e7a26505f0889101e0da91ffe91).
```powershell
scoop install kubescape
```

## Krew
```bash
kubectl krew update
kubectl krew install kubescape
kubectl kubescape
```

## Snap
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/kubescape)

## NixOS or with nix
> **Note**: This method is community-supported. If you are having trouble, please reach out to [NixOS support](https://nixos.wiki/wiki/Support).

You can use `nix` on Linux or macOS.

Try it out in an ephemeral shell: `nix-shell -p kubescape`.

NixOS:

```
  # your other config ...
  environment.systemPackages = with pkgs; [
    # your other packages ...
    kubescape
  ];
```

home-manager:

```
  # your other config ...
  home.packages = with pkgs; [
    # your other packages ...
    kubescape
  ];
```

Or, to your profile (not preferred): `nix-env --install -A nixpkgs.kubescape`.
