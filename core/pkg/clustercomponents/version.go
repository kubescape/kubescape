package clustercomponents

import (
	"fmt"
	"regexp"
	"strings"
)

type Component string

const (
	APIServer  Component = "kube-apiserver"
	Kubelet    Component = "kubelet"
	Containerd Component = "containerd"
	CRIO       Component = "cri-o"

	// ContainerRuntime is used for gaps when the runtime is unknown.
	ContainerRuntime Component = "container-runtime"
)

type Assessment string

const (
	Verified Assessment = "verified"
	// VendorBuild versions may carry backported fixes.
	VendorBuild Assessment = "vendor-build"
)

type ComponentVersion struct {
	Component  Component  `json:"component"`
	Version    string     `json:"version"`
	RawVersion string     `json:"rawVersion"`
	Assessment Assessment `json:"assessment"`
}

var (
	semverPrefix = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)(.*)$`)
	preRelease   = regexp.MustCompile(`^-(alpha|beta|rc|dev|pre)`)

	kubernetesSuffixes = []knownSuffix{
		{regexp.MustCompile(`^-eks-[0-9a-f]+$`), VendorBuild},
		{regexp.MustCompile(`^-gke\.\d+$`), VendorBuild},
		{regexp.MustCompile(`^\+[0-9a-f]{7,40}$`), VendorBuild}, // OpenShift
		{regexp.MustCompile(`^\+k3s\d+$`), Verified},
		{regexp.MustCompile(`^\+rke2r\d+$`), Verified},
	}

	runtimeSuffixes = []knownSuffix{
		{regexp.MustCompile(`^-k3s\d+$`), VendorBuild},
		{regexp.MustCompile(`^\+bottlerocket$`), VendorBuild},
		{regexp.MustCompile(`^-\d+$`), VendorBuild},                                                // distro package revision, e.g. AKS
		{regexp.MustCompile(`^-\d+(\.\d+)*\.amzn\d+(\.\d+)*$`), VendorBuild},                       // Amazon Linux
		{regexp.MustCompile(`^-\d+(\.\d+)*\.rhaos\d+\.\d+\.git[0-9a-f]+(\.el\d+)?$`), VendorBuild}, // OpenShift CRI-O
	}

	runtimeSchemes = map[string]Component{
		"containerd": Containerd,
		"cri-o":      CRIO,
	}
)

// ParseKubernetesVersion rejects pre-releases and unknown vendor suffixes
// instead of guessing a base version.
func ParseKubernetesVersion(component Component, raw string) (ComponentVersion, error) {
	base, suffix, err := splitVersion(raw, raw)
	if err != nil {
		return ComponentVersion{}, err
	}

	assessment, err := classifySuffix(raw, suffix, kubernetesSuffixes)
	if err != nil {
		return ComponentVersion{}, err
	}
	return ComponentVersion{Component: component, Version: base, RawVersion: raw, Assessment: assessment}, nil
}

// ParseContainerRuntimeVersion accepts upstream releases and the vendor
// package formats listed in runtimeSuffixes; anything else is rejected.
func ParseContainerRuntimeVersion(raw string) (ComponentVersion, error) {
	scheme, v, ok := strings.Cut(raw, "://")
	if !ok {
		return ComponentVersion{}, fmt.Errorf("malformed container runtime version %q", raw)
	}
	component, ok := runtimeSchemes[scheme]
	if !ok {
		return ComponentVersion{}, fmt.Errorf("unsupported container runtime %q", scheme)
	}

	base, suffix, err := splitVersion(raw, v)
	if err != nil {
		return ComponentVersion{}, err
	}

	assessment, err := classifySuffix(raw, suffix, runtimeSuffixes)
	if err != nil {
		return ComponentVersion{}, err
	}
	return ComponentVersion{Component: component, Version: base, RawVersion: raw, Assessment: assessment}, nil
}

type knownSuffix struct {
	pattern    *regexp.Regexp
	assessment Assessment
}

func classifySuffix(raw, suffix string, known []knownSuffix) (Assessment, error) {
	if suffix == "" {
		return Verified, nil
	}
	for _, s := range known {
		if s.pattern.MatchString(suffix) {
			return s.assessment, nil
		}
	}
	return "", fmt.Errorf("unrecognized version suffix in %q", raw)
}

// splitVersion splits version into its release and suffix; errors quote raw.
func splitVersion(raw, version string) (base, suffix string, err error) {
	m := semverPrefix.FindStringSubmatch(strings.TrimSpace(version))
	if m == nil {
		return "", "", fmt.Errorf("unparseable version %q", raw)
	}
	base, suffix = m[1], m[2]
	if suffix != "" && suffix[0] != '-' && suffix[0] != '+' {
		return "", "", fmt.Errorf("unparseable version %q", raw)
	}
	if preRelease.MatchString(suffix) {
		return "", "", fmt.Errorf("pre-release version %q", raw)
	}
	return base, suffix, nil
}
