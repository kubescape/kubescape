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
	preRelease   = regexp.MustCompile(`^-(alpha|beta|rc)`)

	kubernetesSuffixes = []struct {
		pattern    *regexp.Regexp
		assessment Assessment
	}{
		{regexp.MustCompile(`^-eks-[0-9a-f]+$`), VendorBuild},
		{regexp.MustCompile(`^-gke\.\d+$`), VendorBuild},
		{regexp.MustCompile(`^\+[0-9a-f]{7,40}$`), VendorBuild}, // OpenShift
		{regexp.MustCompile(`^\+k3s\d+$`), Verified},
		{regexp.MustCompile(`^\+rke2r\d+$`), Verified},
	}

	runtimeSchemes = map[string]Component{
		"containerd": Containerd,
		"cri-o":      CRIO,
	}
)

// ParseKubernetesVersion rejects pre-releases and unknown vendor suffixes
// instead of guessing a base version.
func ParseKubernetesVersion(component Component, raw string) (ComponentVersion, error) {
	base, suffix, err := splitVersion(raw)
	if err != nil {
		return ComponentVersion{}, err
	}

	assessment := Verified
	if suffix != "" {
		assessment = ""
		for _, s := range kubernetesSuffixes {
			if s.pattern.MatchString(suffix) {
				assessment = s.assessment
				break
			}
		}
		if assessment == "" {
			return ComponentVersion{}, fmt.Errorf("unrecognized version suffix in %q", raw)
		}
	}

	return ComponentVersion{Component: component, Version: base, RawVersion: raw, Assessment: assessment}, nil
}

// ParseContainerRuntimeVersion treats any build suffix as a vendor build.
func ParseContainerRuntimeVersion(raw string) (ComponentVersion, error) {
	scheme, v, ok := strings.Cut(raw, "://")
	if !ok {
		return ComponentVersion{}, fmt.Errorf("malformed container runtime version %q", raw)
	}
	component, ok := runtimeSchemes[scheme]
	if !ok {
		return ComponentVersion{}, fmt.Errorf("unsupported container runtime %q", scheme)
	}

	base, suffix, err := splitVersion(v)
	if err != nil {
		return ComponentVersion{}, err
	}

	assessment := Verified
	if suffix != "" {
		assessment = VendorBuild
	}
	return ComponentVersion{Component: component, Version: base, RawVersion: raw, Assessment: assessment}, nil
}

func splitVersion(raw string) (base, suffix string, err error) {
	m := semverPrefix.FindStringSubmatch(strings.TrimSpace(raw))
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
