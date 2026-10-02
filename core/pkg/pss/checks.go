package pss

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Baseline allowed capabilities per Kubernetes v1.31 PSS specification.
var baselineAllowedCapabilities = map[string]bool{
	"AUDIT_WRITE":      true,
	"CHOWN":            true,
	"DAC_OVERRIDE":     true,
	"FOWNER":           true,
	"FSETID":           true,
	"KILL":             true,
	"MKNOD":            true,
	"NET_BIND_SERVICE": true,
	"SETFCAP":          true,
	"SETGID":           true,
	"SETPCAP":          true,
	"SETUID":           true,
	"SYS_CHROOT":       true,
}

// Restricted allowed volume types per Kubernetes v1.31 PSS specification.
var restrictedAllowedVolumeTypes = map[string]bool{
	"configMap":             true,
	"csi":                   true,
	"downwardAPI":           true,
	"emptyDir":              true,
	"ephemeral":             true,
	"persistentVolumeClaim": true,
	"projected":             true,
	"secret":                true,
}

const restrictedVolumeTypesList = "configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret"

// Safe sysctls allowed under Baseline per Kubernetes v1.31 PSS specification.
var allowedSysctls = map[string]bool{
	"kernel.shm_rmid_forced":              true,
	"net.ipv4.ip_local_port_range":        true,
	"net.ipv4.ip_local_reserved_ports":    true,
	"net.ipv4.ip_unprivileged_port_start": true,
	"net.ipv4.tcp_syncookies":             true,
	"net.ipv4.ping_group_range":           true,
	"net.ipv4.tcp_keepalive_time":         true,
	"net.ipv4.tcp_fin_timeout":            true,
	"net.ipv4.tcp_keepalive_intvl":        true,
	"net.ipv4.tcp_keepalive_probes":       true,
}

// Allowed SELinux type values under Baseline.
var allowedSELinuxTypes = map[string]bool{
	"container_t":        true,
	"container_init_t":   true,
	"container_kvm_t":    true,
	"container_engine_t": true,
}

// checkHostNamespaces implements PSS Baseline §HostNamespaces and §HostProcess (pod scope).
// HostNetwork, HostPID, HostIPC, and windowsOptions.hostProcess must all be false or unset.
func checkHostNamespaces(podSpec corev1.PodSpec) []Violation {
	var violations []Violation
	if podSpec.HostNetwork {
		violations = append(violations, Violation{
			Check:       "HostNetwork",
			Level:       Baseline,
			Description: "pod has hostNetwork enabled",
		})
	}
	if podSpec.HostPID {
		violations = append(violations, Violation{
			Check:       "HostPID",
			Level:       Baseline,
			Description: "pod has hostPID enabled",
		})
	}
	if podSpec.HostIPC {
		violations = append(violations, Violation{
			Check:       "HostIPC",
			Level:       Baseline,
			Description: "pod has hostIPC enabled",
		})
	}
	if sc := podSpec.SecurityContext; sc != nil && sc.WindowsOptions != nil &&
		sc.WindowsOptions.HostProcess != nil && *sc.WindowsOptions.HostProcess {
		violations = append(violations, Violation{
			Check:       "HostProcess",
			Level:       Baseline,
			Description: "pod sets windowsOptions.hostProcess to true",
		})
	}
	return violations
}

// checkHostProcess implements PSS Baseline §HostProcess for container scope.
// Windows containers must not set windowsOptions.hostProcess to true.
func checkHostProcess(c corev1.Container, containerType string) []Violation {
	if sc := c.SecurityContext; sc != nil && sc.WindowsOptions != nil &&
		sc.WindowsOptions.HostProcess != nil && *sc.WindowsOptions.HostProcess {
		return []Violation{
			{
				Check:         "HostProcess",
				Level:         Baseline,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q sets windowsOptions.hostProcess to true", containerType, c.Name),
			},
		}
	}
	return nil
}

// checkHostPorts implements PSS Baseline §HostPorts.
// Container ports must not bind a hostPort > 0.
func checkHostPorts(podSpec corev1.PodSpec) []Violation {
	var violations []Violation
	checkPorts := func(containers []corev1.Container, kind string) {
		for _, c := range containers {
			for _, p := range c.Ports {
				if p.HostPort > 0 {
					violations = append(violations, Violation{
						Check:         "HostPorts",
						Level:         Baseline,
						Container:     c.Name,
						ContainerType: kind,
						Description:   fmt.Sprintf("%s %q binds hostPort %d", kind, c.Name, p.HostPort),
					})
				}
			}
		}
	}

	checkPorts(podSpec.Containers, "container")
	checkPorts(podSpec.InitContainers, "initContainer")
	for _, ec := range podSpec.EphemeralContainers {
		c := ephemeralToContainer(ec)
		for _, p := range c.Ports {
			if p.HostPort > 0 {
				violations = append(violations, Violation{
					Check:         "HostPorts",
					Level:         Baseline,
					Container:     c.Name,
					ContainerType: "ephemeralContainer",
					Description:   fmt.Sprintf("ephemeralContainer %q binds hostPort %d", c.Name, p.HostPort),
				})
			}
		}
	}
	return violations
}

// checkVolumes implements PSS Baseline & Restricted §Volumes.
// Baseline: hostPath volumes are forbidden.
// Restricted: only allowed volume types are permitted.
func checkVolumes(podSpec corev1.PodSpec) []Violation {
	var violations []Violation
	for _, vol := range podSpec.Volumes {
		if vol.HostPath != nil {
			violations = append(violations, Violation{
				Check:       "HostPath",
				Level:       Baseline,
				Description: fmt.Sprintf("pod uses hostPath volume %q", vol.Name),
			})
		}
		volType := volumeTypeName(vol)
		if !restrictedAllowedVolumeTypes[volType] {
			violations = append(violations, Violation{
				Check:       "Volumes",
				Level:       Restricted,
				Description: fmt.Sprintf("volume %q uses type %q; Restricted allows only: %s", vol.Name, volType, restrictedVolumeTypesList),
			})
		}
	}
	return violations
}

// checkSysctls implements PSS Baseline §Sysctls.
// Sysctls must be unset or limited to the safe sysctls set.
func checkSysctls(podSpec corev1.PodSpec) []Violation {
	if podSpec.SecurityContext == nil {
		return nil
	}
	var violations []Violation
	for _, s := range podSpec.SecurityContext.Sysctls {
		if !allowedSysctls[s.Name] {
			violations = append(violations, Violation{
				Check:       "Sysctls",
				Level:       Baseline,
				Description: fmt.Sprintf("sysctl %q is not in the allowed safe sysctls set", s.Name),
			})
		}
	}
	return violations
}

// checkPrivileged implements PSS Baseline §PrivilegedContainers.
// Containers must not run in privileged mode.
func checkPrivileged(c corev1.Container, containerType string) []Violation {
	if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
		return []Violation{
			{
				Check:         "Privileged",
				Level:         Baseline,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q is privileged", containerType, c.Name),
			},
		}
	}
	return nil
}

// checkCapabilities implements PSS Baseline & Restricted §Capabilities.
// Baseline: only baseline-allowed capabilities may be added.
// Restricted: must drop ALL; only NET_BIND_SERVICE may be added.
func checkCapabilities(c corev1.Container, containerType string) []Violation {
	var violations []Violation
	sc := c.SecurityContext

	if sc == nil || sc.Capabilities == nil {
		violations = append(violations, Violation{
			Check:         "Capabilities",
			Level:         Restricted,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q must drop ALL capabilities; securityContext.capabilities is unset", containerType, c.Name),
		})
		return violations
	}

	// Baseline: only allowed capabilities may be added
	for _, cap := range sc.Capabilities.Add {
		if !baselineAllowedCapabilities[string(cap)] {
			violations = append(violations, Violation{
				Check:         "Capabilities",
				Level:         Baseline,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q adds capability %s; not in Baseline allowed set", containerType, c.Name, cap),
			})
		}
	}

	// Restricted: must drop ALL
	hasDropAll := false
	for _, cap := range sc.Capabilities.Drop {
		if cap == "ALL" {
			hasDropAll = true
			break
		}
	}
	if !hasDropAll {
		violations = append(violations, Violation{
			Check:         "Capabilities",
			Level:         Restricted,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q capabilities.drop must include ALL", containerType, c.Name),
		})
	}

	// Restricted: only NET_BIND_SERVICE may be added
	for _, cap := range sc.Capabilities.Add {
		if cap != "NET_BIND_SERVICE" {
			violations = append(violations, Violation{
				Check:         "Capabilities",
				Level:         Restricted,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q adds capability %s; Restricted only allows NET_BIND_SERVICE", containerType, c.Name, cap),
			})
		}
	}

	return violations
}

// checkProcMount implements PSS Baseline §ProcMount.
// procMount must be Default or unset.
func checkProcMount(c corev1.Container, containerType string) []Violation {
	if c.SecurityContext != nil && c.SecurityContext.ProcMount != nil && *c.SecurityContext.ProcMount != corev1.DefaultProcMount {
		return []Violation{
			{
				Check:         "ProcMount",
				Level:         Baseline,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q sets procMount %q; must be Default or unset", containerType, c.Name, *c.SecurityContext.ProcMount),
			},
		}
	}
	return nil
}

// checkPodSELinux implements PSS Baseline §SELinux for pod-level settings.
func checkPodSELinux(podSpec corev1.PodSpec) []Violation {
	if podSpec.SecurityContext == nil || podSpec.SecurityContext.SELinuxOptions == nil {
		return nil
	}
	var violations []Violation
	opt := podSpec.SecurityContext.SELinuxOptions
	if opt.User != "" {
		violations = append(violations, Violation{
			Check:       "SELinuxOptions",
			Level:       Baseline,
			Description: fmt.Sprintf("pod sets custom SELinux user %q; must be unset", opt.User),
		})
	}
	if opt.Role != "" {
		violations = append(violations, Violation{
			Check:       "SELinuxOptions",
			Level:       Baseline,
			Description: fmt.Sprintf("pod sets custom SELinux role %q; must be unset", opt.Role),
		})
	}
	if opt.Type != "" && !allowedSELinuxTypes[opt.Type] {
		violations = append(violations, Violation{
			Check:       "SELinuxOptions",
			Level:       Baseline,
			Description: fmt.Sprintf("pod sets custom SELinux type %q; not in allowed set", opt.Type),
		})
	}
	return violations
}

// checkSELinux implements PSS Baseline §SELinux for container-level settings.
func checkSELinux(c corev1.Container, containerType string) []Violation {
	if c.SecurityContext == nil || c.SecurityContext.SELinuxOptions == nil {
		return nil
	}
	var violations []Violation
	opt := c.SecurityContext.SELinuxOptions
	if opt.User != "" {
		violations = append(violations, Violation{
			Check:         "SELinuxOptions",
			Level:         Baseline,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q sets custom SELinux user %q; must be unset", containerType, c.Name, opt.User),
		})
	}
	if opt.Role != "" {
		violations = append(violations, Violation{
			Check:         "SELinuxOptions",
			Level:         Baseline,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q sets custom SELinux role %q; must be unset", containerType, c.Name, opt.Role),
		})
	}
	if opt.Type != "" && !allowedSELinuxTypes[opt.Type] {
		violations = append(violations, Violation{
			Check:         "SELinuxOptions",
			Level:         Baseline,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q sets custom SELinux type %q; not in allowed set", containerType, c.Name, opt.Type),
		})
	}
	return violations
}

// checkPodSeccompProfile implements PSS Baseline §Seccomp at the pod level.
// RuntimeDefault, Localhost, or unset are allowed; other types (such as Unconfined) violate Baseline.
func checkPodSeccompProfile(podSpec corev1.PodSpec) []Violation {
	if podSpec.SecurityContext == nil || podSpec.SecurityContext.SeccompProfile == nil {
		return nil
	}

	profileType := podSpec.SecurityContext.SeccompProfile.Type
	if profileType == corev1.SeccompProfileTypeRuntimeDefault ||
		profileType == corev1.SeccompProfileTypeLocalhost {
		return nil
	}

	return []Violation{
		{
			Check:       "SeccompProfile",
			Level:       Baseline,
			Description: "pod seccomp profile must be RuntimeDefault or Localhost",
		},
	}
}

// checkSeccompProfile implements PSS Baseline & Restricted §Seccomp.
// Baseline: profile must not be Unconfined.
// Restricted: profile must be RuntimeDefault or Localhost.
func checkSeccompProfile(podSpec corev1.PodSpec, c corev1.Container, containerType string) []Violation {
	var effectiveProfile *corev1.SeccompProfile
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		effectiveProfile = c.SecurityContext.SeccompProfile
	} else if podSpec.SecurityContext != nil && podSpec.SecurityContext.SeccompProfile != nil {
		effectiveProfile = podSpec.SecurityContext.SeccompProfile
	}

	var violations []Violation

	if effectiveProfile != nil && effectiveProfile.Type == corev1.SeccompProfileTypeUnconfined {
		violations = append(violations, Violation{
			Check:         "SeccompProfile",
			Level:         Baseline,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q has seccomp profile Unconfined", containerType, c.Name),
		})
	}

	if effectiveProfile == nil ||
		(effectiveProfile.Type != corev1.SeccompProfileTypeRuntimeDefault &&
			effectiveProfile.Type != corev1.SeccompProfileTypeLocalhost) {
		violations = append(violations, Violation{
			Check:         "SeccompProfile",
			Level:         Restricted,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q seccomp profile must be RuntimeDefault or Localhost", containerType, c.Name),
		})
	}

	return violations
}

// checkPodAppArmorProfile implements PSS Baseline §AppArmor at the pod level.
// AppArmor profile must not be Unconfined.
func checkPodAppArmorProfile(podSpec corev1.PodSpec) []Violation {
	if podSpec.SecurityContext == nil ||
		podSpec.SecurityContext.AppArmorProfile == nil ||
		podSpec.SecurityContext.AppArmorProfile.Type != corev1.AppArmorProfileTypeUnconfined {
		return nil
	}
	return []Violation{
		{
			Check:       "AppArmorProfile",
			Level:       Baseline,
			Description: "pod has AppArmor profile Unconfined",
		},
	}
}

// checkAppArmorProfile implements PSS Baseline §AppArmor.
// Profile must not be Unconfined.
func checkAppArmorProfile(podSpec corev1.PodSpec, c corev1.Container, containerType string) []Violation {
	var effectiveProfile *corev1.AppArmorProfile
	if c.SecurityContext != nil && c.SecurityContext.AppArmorProfile != nil {
		effectiveProfile = c.SecurityContext.AppArmorProfile
	} else if podSpec.SecurityContext != nil && podSpec.SecurityContext.AppArmorProfile != nil {
		effectiveProfile = podSpec.SecurityContext.AppArmorProfile
	}

	var violations []Violation
	if effectiveProfile != nil && effectiveProfile.Type == corev1.AppArmorProfileTypeUnconfined {
		violations = append(violations, Violation{
			Check:         "AppArmorProfile",
			Level:         Baseline,
			Container:     c.Name,
			ContainerType: containerType,
			Description:   fmt.Sprintf("%s %q has AppArmor profile Unconfined", containerType, c.Name),
		})
	}
	return violations
}

// checkAllowPrivilegeEscalation implements PSS Restricted §AllowPrivilegeEscalation.
// allowPrivilegeEscalation must be false.
func checkAllowPrivilegeEscalation(c corev1.Container, containerType string) []Violation {
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		return []Violation{
			{
				Check:         "AllowPrivilegeEscalation",
				Level:         Restricted,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q allowPrivilegeEscalation must be false", containerType, c.Name),
			},
		}
	}
	return nil
}

// checkRunAsNonRoot implements PSS Restricted §RunAsNonRoot.
// runAsNonRoot must be true at container or pod level, and explicit pod-level false is rejected.
func checkRunAsNonRoot(podSpec corev1.PodSpec, c corev1.Container, containerType string) []Violation {
	var runAsNonRoot *bool
	if podSpec.SecurityContext != nil &&
		podSpec.SecurityContext.RunAsNonRoot != nil &&
		!*podSpec.SecurityContext.RunAsNonRoot {
		runAsNonRoot = podSpec.SecurityContext.RunAsNonRoot
	} else if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		runAsNonRoot = c.SecurityContext.RunAsNonRoot
	} else if podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsNonRoot != nil {
		runAsNonRoot = podSpec.SecurityContext.RunAsNonRoot
	}

	if runAsNonRoot == nil || !*runAsNonRoot {
		return []Violation{
			{
				Check:         "RunAsNonRoot",
				Level:         Restricted,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q must set runAsNonRoot to true", containerType, c.Name),
			},
		}
	}
	return nil
}

// checkRunAsUser implements PSS Restricted §RunAsUser.
// runAsUser must not be 0 (root). Pod-level 0 is rejected regardless of container overrides.
func checkRunAsUser(podSpec corev1.PodSpec, c corev1.Container, containerType string) []Violation {
	var runAsUser *int64
	if podSpec.SecurityContext != nil &&
		podSpec.SecurityContext.RunAsUser != nil &&
		*podSpec.SecurityContext.RunAsUser == 0 {
		runAsUser = podSpec.SecurityContext.RunAsUser
	} else if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		runAsUser = c.SecurityContext.RunAsUser
	} else if podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsUser != nil {
		runAsUser = podSpec.SecurityContext.RunAsUser
	}

	if runAsUser != nil && *runAsUser == 0 {
		return []Violation{
			{
				Check:         "RunAsUser",
				Level:         Restricted,
				Container:     c.Name,
				ContainerType: containerType,
				Description:   fmt.Sprintf("%s %q runAsUser must not be 0", containerType, c.Name),
			},
		}
	}
	return nil
}

const appArmorAnnotationPrefix = "container.apparmor.security.beta.kubernetes.io/"

// checkLegacyAppArmor implements PSS Baseline §AppArmor for legacy container annotations (pre-v1.30).
// In Kubernetes v1.31, all annotations matching the container.apparmor.security.beta.kubernetes.io/
// prefix are validated independently at pod scope against an allowlist: empty, "runtime/default",
// or profiles starting with "localhost/". Any other value is forbidden under Baseline.
func checkLegacyAppArmor(annotations map[string]string) []Violation {
	if len(annotations) == 0 {
		return nil
	}

	var violations []Violation
	for k, v := range annotations {
		if strings.HasPrefix(k, appArmorAnnotationPrefix) {
			if !isAllowedLegacyAppArmorValue(v) {
				containerName := strings.TrimPrefix(k, appArmorAnnotationPrefix)
				containerType := "container"
				if containerName == "" {
					containerType = "pod"
				}
				violations = append(violations, Violation{
					Check:         "AppArmorProfile",
					Level:         Baseline,
					Container:     containerName,
					ContainerType: containerType,
					Description: fmt.Sprintf("%s %q has forbidden legacy AppArmor profile %q; allowed values are empty, %q, or %q",
						containerType, containerName, v, corev1.DeprecatedAppArmorBetaProfileRuntimeDefault, corev1.DeprecatedAppArmorBetaProfileNamePrefix+"*"),
				})
			}
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		return violations[i].Container < violations[j].Container
	})
	return violations
}

func isAllowedLegacyAppArmorValue(profile string) bool {
	return len(profile) == 0 ||
		profile == corev1.DeprecatedAppArmorBetaProfileRuntimeDefault ||
		strings.HasPrefix(profile, corev1.DeprecatedAppArmorBetaProfileNamePrefix)
}

// volumeTypeName returns the name of the active volume source field.
func volumeTypeName(vol corev1.Volume) string {
	vs := vol.VolumeSource
	switch {
	case vs.HostPath != nil:
		return "hostPath"
	case vs.EmptyDir != nil:
		return "emptyDir"
	case vs.GCEPersistentDisk != nil:
		return "gcePersistentDisk"
	case vs.AWSElasticBlockStore != nil:
		return "awsElasticBlockStore"
	case vs.GitRepo != nil:
		return "gitRepo"
	case vs.Secret != nil:
		return "secret"
	case vs.NFS != nil:
		return "nfs"
	case vs.ISCSI != nil:
		return "iscsi"
	case vs.Glusterfs != nil:
		return "glusterfs"
	case vs.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case vs.RBD != nil:
		return "rbd"
	case vs.FlexVolume != nil:
		return "flexVolume"
	case vs.Cinder != nil:
		return "cinder"
	case vs.CephFS != nil:
		return "cephfs"
	case vs.Flocker != nil:
		return "flocker"
	case vs.DownwardAPI != nil:
		return "downwardAPI"
	case vs.FC != nil:
		return "fc"
	case vs.AzureFile != nil:
		return "azureFile"
	case vs.ConfigMap != nil:
		return "configMap"
	case vs.VsphereVolume != nil:
		return "vsphereVolume"
	case vs.Quobyte != nil:
		return "quobyte"
	case vs.AzureDisk != nil:
		return "azureDisk"
	case vs.PhotonPersistentDisk != nil:
		return "photonPersistentDisk"
	case vs.Projected != nil:
		return "projected"
	case vs.PortworxVolume != nil:
		return "portworxVolume"
	case vs.ScaleIO != nil:
		return "scaleIO"
	case vs.StorageOS != nil:
		return "storageos"
	case vs.CSI != nil:
		return "csi"
	case vs.Ephemeral != nil:
		return "ephemeral"
	case vs.Image != nil:
		return "image"
	default:
		return "unknown"
	}
}

// ephemeralToContainer converts an EphemeralContainer to a standard Container
// to share identical security check logic.
func ephemeralToContainer(ec corev1.EphemeralContainer) corev1.Container {
	return corev1.Container(ec.EphemeralContainerCommon)
}
