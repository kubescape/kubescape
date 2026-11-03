package clustercomponents

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const Kernel Component = "kernel"

// Distro identifiers match the Grype distro types the package is looked up in.
const (
	DistroAmazonLinux = "amazonlinux"
	DistroRHEL        = "redhat"
	DistroRocky       = "rockylinux"
	DistroAlma        = "almalinux"
	DistroUbuntu      = "ubuntu"
	DistroDebian      = "debian"
)

const (
	PackageTypeRPM = "rpm"
	PackageTypeDeb = "deb"
)

// KernelPackage is the installed kernel package that distro advisories are
// keyed to, reconstructed from the node's kernel evidence.
type KernelPackage struct {
	Distro        string `json:"distro"`
	DistroVersion string `json:"distroVersion"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Version       string `json:"version"`
}

var (
	errNoKernelVersionData = errors.New("KernelVersion host data not found")
	errNoOSReleaseData     = errors.New("OsReleaseFile host data not found")

	rpmKernelRelease = regexp.MustCompile(`^((\d+)\.(\d+)\.\d+-[0-9][0-9A-Za-z._]*?)\.(x86_64|aarch64)$`)
	amznTag          = regexp.MustCompile(`\.amzn(2|2023)$`)
	elTag            = regexp.MustCompile(`\.el(\d+)(_\d+)?$`)

	ubuntuKernelRelease = regexp.MustCompile(`^(\d+\.\d+)\.(\d+)-(\d+)-([a-z0-9]+)$`)
	ubuntuBuildTag      = regexp.MustCompile(`#(\d+)(~\d+\.\d+(?:\.\d+)*)?-Ubuntu `)

	debianPackageVersion = regexp.MustCompile(` Debian (\d+\.\d+(?:\.\d+)?-\d+(?:\+deb\d+u\d+)?) \(`)

	// Kernel series each Ubuntu release ships as its GA kernel.
	ubuntuGASeries = map[string]string{
		"20.04": "5.4",
		"22.04": "5.15",
		"24.04": "6.8",
	}
	// Flavours whose GA source package is linux-<flavour>, or linux for
	// generic. Anything else is a gap rather than a guessed package.
	ubuntuFlavours = map[string]bool{
		"generic": true,
		"aws":     true,
		"azure":   true,
		"gcp":     true,
		"oracle":  true,
	}
	// Backport kernels per release and series, with the flavours that publish
	// a linux-<flavour>-<series> (linux-hwe-<series> for generic) source
	// package. Not every flavour gets every backport, e.g. there is no
	// linux-oracle-6.2 on 22.04, so a missing entry is a gap.
	ubuntuBackports = map[string]map[string][]string{
		"20.04": {
			"5.8":  {"generic", "aws", "azure", "gcp", "oracle"},
			"5.11": {"generic", "aws", "azure", "gcp", "oracle"},
			"5.13": {"generic", "aws", "azure", "gcp", "oracle"},
			"5.15": {"generic", "aws", "azure", "gcp", "oracle"},
		},
		"22.04": {
			"5.19": {"generic", "aws", "azure", "gcp"},
			"6.2":  {"generic", "aws", "azure", "gcp"},
			"6.5":  {"generic", "aws", "azure", "gcp", "oracle"},
			"6.8":  {"generic", "aws", "azure", "gcp", "oracle"},
		},
		"24.04": {
			"6.11": {"generic", "azure", "gcp"},
			"6.14": {"generic", "aws", "azure", "gcp", "oracle"},
		},
	}
	// Amazon Linux kernels whose package is plain "kernel"; AL2023 ships
	// newer series as separately named packages.
	amazonKernelPackages = map[string]map[string]string{
		"2":    {"4.14": "kernel", "5.4": "kernel", "5.10": "kernel", "5.15": "kernel"},
		"2023": {"6.1": "kernel", "6.12": "kernel6.12"},
	}
)

// ReconstructKernel derives the installed kernel package from the node's
// evidence. Only reconstructions that are exact are supported; anything else
// is an error so the kernel is reported as a coverage gap, never guessed.
func ReconstructKernel(k KernelEvidence) (KernelPackage, error) {
	if k.Release == "" {
		return KernelPackage{}, errors.New("kernel version not reported")
	}
	switch osFamily(k) {
	case DistroAmazonLinux:
		return amazonKernel(k.Release)
	case DistroRHEL, DistroRocky, DistroAlma:
		return elKernel(osFamily(k), k.Release)
	case DistroUbuntu:
		return ubuntuKernel(k)
	case DistroDebian:
		return debianKernel(k)
	}
	if k.OSImage == "" {
		return KernelPackage{}, fmt.Errorf("unsupported kernel %q: operating system not reported", k.Release)
	}
	return KernelPackage{}, fmt.Errorf("unsupported kernel %q on %q", k.Release, k.OSImage)
}

// osFamily prefers the os-release ID and falls back to the node's OS image.
func osFamily(k KernelEvidence) string {
	switch k.OSID {
	case "amzn":
		return DistroAmazonLinux
	case "rhel":
		return DistroRHEL
	case "rocky":
		return DistroRocky
	case "almalinux":
		return DistroAlma
	case "ubuntu":
		return DistroUbuntu
	case "debian":
		return DistroDebian
	case "":
	default:
		return ""
	}
	image := k.OSImage
	switch {
	case strings.HasPrefix(image, "Amazon Linux "):
		return DistroAmazonLinux
	case strings.HasPrefix(image, "Red Hat Enterprise Linux ") && !strings.HasPrefix(image, "Red Hat Enterprise Linux CoreOS"):
		return DistroRHEL
	case strings.HasPrefix(image, "Rocky Linux "):
		return DistroRocky
	case strings.HasPrefix(image, "AlmaLinux "):
		return DistroAlma
	case strings.HasPrefix(image, "Ubuntu "):
		return DistroUbuntu
	case strings.HasPrefix(image, "Debian GNU/Linux "):
		return DistroDebian
	}
	return ""
}

func amazonKernel(release string) (KernelPackage, error) {
	m := rpmKernelRelease.FindStringSubmatch(release)
	if m == nil {
		return KernelPackage{}, fmt.Errorf("unrecognized Amazon Linux kernel release %q", release)
	}
	tag := amznTag.FindStringSubmatch(m[1])
	if tag == nil {
		return KernelPackage{}, fmt.Errorf("unrecognized Amazon Linux kernel release %q", release)
	}
	name, ok := amazonKernelPackages[tag[1]][m[2]+"."+m[3]]
	if !ok {
		return KernelPackage{}, fmt.Errorf("unsupported Amazon Linux %s kernel series %s.%s", tag[1], m[2], m[3])
	}
	return KernelPackage{Distro: DistroAmazonLinux, DistroVersion: tag[1], Type: PackageTypeRPM, Name: name, Version: m[1]}, nil
}

func elKernel(distro, release string) (KernelPackage, error) {
	m := rpmKernelRelease.FindStringSubmatch(release)
	if m == nil {
		return KernelPackage{}, fmt.Errorf("unrecognized Enterprise Linux kernel release %q", release)
	}
	tag := elTag.FindStringSubmatch(m[1])
	if tag == nil {
		return KernelPackage{}, fmt.Errorf("unrecognized Enterprise Linux kernel release %q", release)
	}
	return KernelPackage{Distro: distro, DistroVersion: tag[1], Type: PackageTypeRPM, Name: "kernel", Version: m[1]}, nil
}

// ubuntuKernel rebuilds the package version from uname -r and the build tag
// in /proc/version: 5.15.0-1057-aws with #63~20.04.1-Ubuntu is
// 5.15.0-1057.63~20.04.1 of linux-aws-5.15 on 20.04.
func ubuntuKernel(k KernelEvidence) (KernelPackage, error) {
	m := ubuntuKernelRelease.FindStringSubmatch(k.Release)
	if m == nil {
		return KernelPackage{}, fmt.Errorf("unrecognized Ubuntu kernel release %q", k.Release)
	}
	series, patch, abi, flavour := m[1], m[2], m[3], m[4]
	if !ubuntuFlavours[flavour] {
		return KernelPackage{}, fmt.Errorf("unsupported Ubuntu kernel flavour %q", flavour)
	}
	if k.ProcVersion == "" {
		return KernelPackage{}, errNoKernelVersionData
	}
	if k.OSVersionID == "" {
		return KernelPackage{}, errNoOSReleaseData
	}
	tag := ubuntuBuildTag.FindStringSubmatch(k.ProcVersion)
	if tag == nil || !strings.Contains(k.ProcVersion, " "+k.Release+" ") {
		return KernelPackage{}, fmt.Errorf("kernel build tag for %q not found in /proc/version", k.Release)
	}
	upload, backport := tag[1], tag[2]

	gaSeries, ok := ubuntuGASeries[k.OSVersionID]
	if !ok {
		return KernelPackage{}, fmt.Errorf("unsupported Ubuntu release %q", k.OSVersionID)
	}
	var name string
	switch {
	case series == gaSeries && backport == "":
		name = "linux"
		if flavour != "generic" {
			name += "-" + flavour
		}
	case series != gaSeries && strings.HasPrefix(backport, "~"+k.OSVersionID+".") && slices.Contains(ubuntuBackports[k.OSVersionID][series], flavour):
		name = "linux-hwe-" + series
		if flavour != "generic" {
			name = "linux-" + flavour + "-" + series
		}
	default:
		return KernelPackage{}, fmt.Errorf("kernel %q does not match a known Ubuntu %s source package", k.Release, k.OSVersionID)
	}
	return KernelPackage{
		Distro:        DistroUbuntu,
		DistroVersion: k.OSVersionID,
		Type:          PackageTypeDeb,
		Name:          name,
		Version:       series + "." + patch + "-" + abi + "." + upload + backport,
	}, nil
}

// debianKernel reads the package version Debian embeds in /proc/version,
// e.g. "Debian 6.1.76-1 (2024-02-01)".
func debianKernel(k KernelEvidence) (KernelPackage, error) {
	if k.ProcVersion == "" {
		return KernelPackage{}, errNoKernelVersionData
	}
	if k.OSVersionID == "" {
		return KernelPackage{}, errNoOSReleaseData
	}
	m := debianPackageVersion.FindStringSubmatch(k.ProcVersion)
	if m == nil {
		return KernelPackage{}, fmt.Errorf("Debian kernel package version for %q not found in /proc/version", k.Release)
	}
	return KernelPackage{Distro: DistroDebian, DistroVersion: k.OSVersionID, Type: PackageTypeDeb, Name: "linux", Version: m[1]}, nil
}
