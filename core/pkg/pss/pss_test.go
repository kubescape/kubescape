package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// Helper builders for constructing test PodSpecs
func podSpec(opts ...func(*corev1.PodSpec)) corev1.PodSpec {
	ps := corev1.PodSpec{
		Containers: []corev1.Container{{Name: "main"}},
	}
	for _, o := range opts {
		o(&ps)
	}
	return ps
}

func ensureContainerSecurityContext(c *corev1.Container) {
	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}
}

func ensurePodSecurityContext(ps *corev1.PodSpec) {
	if ps.SecurityContext == nil {
		ps.SecurityContext = &corev1.PodSecurityContext{}
	}
}

func withHostNetwork(ps *corev1.PodSpec) { ps.HostNetwork = true }
func withHostPID(ps *corev1.PodSpec)     { ps.HostPID = true }
func withHostIPC(ps *corev1.PodSpec)     { ps.HostIPC = true }

func withHostPort(port int32) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ps.Containers[0].Ports = append(ps.Containers[0].Ports, corev1.ContainerPort{
			Name:     "http",
			HostPort: port,
		})
	}
}

func withPrivileged(ps *corev1.PodSpec) {
	ensureContainerSecurityContext(&ps.Containers[0])
	t := true
	ps.Containers[0].SecurityContext.Privileged = &t
}

func withCapAdd(caps ...corev1.Capability) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		if ps.Containers[0].SecurityContext.Capabilities == nil {
			ps.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{}
		}
		ps.Containers[0].SecurityContext.Capabilities.Add = append(
			ps.Containers[0].SecurityContext.Capabilities.Add, caps...)
	}
}

func withDropAll(ps *corev1.PodSpec) {
	ensureContainerSecurityContext(&ps.Containers[0])
	if ps.Containers[0].SecurityContext.Capabilities == nil {
		ps.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{}
	}
	ps.Containers[0].SecurityContext.Capabilities.Drop = append(
		ps.Containers[0].SecurityContext.Capabilities.Drop, "ALL")
}

func withCapDrop(caps ...corev1.Capability) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		if ps.Containers[0].SecurityContext.Capabilities == nil {
			ps.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{}
		}
		ps.Containers[0].SecurityContext.Capabilities.Drop = append(
			ps.Containers[0].SecurityContext.Capabilities.Drop, caps...)
	}
}

func withHostPath(name, path string) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ps.Volumes = append(ps.Volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: path},
			},
		})
	}
}

func withVolume(name string, vs corev1.VolumeSource) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ps.Volumes = append(ps.Volumes, corev1.Volume{
			Name:         name,
			VolumeSource: vs,
		})
	}
}

func withProcMount(pm corev1.ProcMountType) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.ProcMount = &pm
	}
}

func withSysctl(name, val string) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		ps.SecurityContext.Sysctls = append(ps.SecurityContext.Sysctls, corev1.Sysctl{
			Name:  name,
			Value: val,
		})
	}
}

func withPodSELinux(user, role, typ string) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		ps.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{
			User: user,
			Role: role,
			Type: typ,
		}
	}
}

func withContainerSELinux(user, role, typ string) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{
			User: user,
			Role: role,
			Type: typ,
		}
	}
}

func withPodSeccomp(typ corev1.SeccompProfileType) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		ps.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: typ}
	}
}

func withContainerSeccomp(typ corev1.SeccompProfileType) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: typ}
	}
}

func withPodAppArmor(typ corev1.AppArmorProfileType) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		ps.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: typ}
	}
}

func withContainerAppArmor(typ corev1.AppArmorProfileType) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: typ}
	}
}

func withAllowPrivilegeEscalation(val bool) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.AllowPrivilegeEscalation = &val
	}
}

func withPodRunAsNonRoot(val bool) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		ps.SecurityContext.RunAsNonRoot = &val
	}
}

func withContainerRunAsNonRoot(val bool) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.RunAsNonRoot = &val
	}
}

func withPodRunAsUser(uid int64) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		ps.SecurityContext.RunAsUser = &uid
	}
}

func withContainerRunAsUser(uid int64) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		ps.Containers[0].SecurityContext.RunAsUser = &uid
	}
}

func withPodHostProcess(val bool) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensurePodSecurityContext(ps)
		if ps.SecurityContext.WindowsOptions == nil {
			ps.SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{}
		}
		ps.SecurityContext.WindowsOptions.HostProcess = &val
	}
}

func withContainerHostProcess(val bool) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ensureContainerSecurityContext(&ps.Containers[0])
		if ps.Containers[0].SecurityContext.WindowsOptions == nil {
			ps.Containers[0].SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{}
		}
		ps.Containers[0].SecurityContext.WindowsOptions.HostProcess = &val
	}
}

func withPodOS(name corev1.OSName) func(*corev1.PodSpec) {
	return func(ps *corev1.PodSpec) {
		ps.OS = &corev1.PodOS{Name: name}
	}
}

func compliantRestrictedPod() corev1.PodSpec {
	f := false
	t := true
	uid := int64(10001)
	return corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   &t,
			RunAsUser:      &uid,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &f,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
			},
		},
	}
}

func checksFromViolations(violations []Violation) map[string]bool {
	res := make(map[string]bool, len(violations))
	for _, v := range violations {
		res[v.Check] = true
	}
	return res
}

func TestEvaluate_Privileged(t *testing.T) {
	// Evaluating at Privileged level should always return nil / 0 violations
	ps := podSpec(withHostNetwork, withHostPID, withHostIPC, withPrivileged)
	violations := Evaluate(ps, Privileged)
	if len(violations) != 0 {
		t.Errorf("Privileged level returned %d violations, want 0", len(violations))
	}
}

func TestEvaluate_BaselineChecks(t *testing.T) {
	tests := []struct {
		name       string
		podSpec    corev1.PodSpec
		wantChecks []string
	}{
		{
			name:       "rejects HostNetwork",
			podSpec:    podSpec(withHostNetwork),
			wantChecks: []string{"HostNetwork"},
		},
		{
			name:       "rejects HostPID",
			podSpec:    podSpec(withHostPID),
			wantChecks: []string{"HostPID"},
		},
		{
			name:       "rejects HostIPC",
			podSpec:    podSpec(withHostIPC),
			wantChecks: []string{"HostIPC"},
		},
		{
			name:       "rejects HostPort > 0",
			podSpec:    podSpec(withHostPort(8080)),
			wantChecks: []string{"HostPorts"},
		},
		{
			name:       "rejects Privileged container",
			podSpec:    podSpec(withPrivileged),
			wantChecks: []string{"Privileged"},
		},
		{
			name:       "rejects disallowed capability addition (NET_RAW)",
			podSpec:    podSpec(withCapAdd("NET_RAW")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects disallowed capability addition (SYS_ADMIN)",
			podSpec:    podSpec(withCapAdd("SYS_ADMIN")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects lowercase capability addition under Baseline",
			podSpec:    podSpec(withCapAdd("chown")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects whitespace padded capability addition under Baseline",
			podSpec:    podSpec(withCapAdd(" CHOWN ")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects hostPath volume",
			podSpec:    podSpec(withHostPath("host-vol", "/var/run")),
			wantChecks: []string{"HostPath"},
		},
		{
			name:       "rejects unmasked procMount",
			podSpec:    podSpec(withProcMount(corev1.UnmaskedProcMount)),
			wantChecks: []string{"ProcMount"},
		},
		{
			name:       "rejects unsafe sysctl",
			podSpec:    podSpec(withSysctl("net.ipv4.ip_forward", "1")),
			wantChecks: []string{"Sysctls"},
		},
		{
			name:       "rejects pod custom SELinux user",
			podSpec:    podSpec(withPodSELinux("custom_u", "", "")),
			wantChecks: []string{"SELinuxOptions"},
		},
		{
			name:       "rejects pod custom SELinux role",
			podSpec:    podSpec(withPodSELinux("", "custom_r", "")),
			wantChecks: []string{"SELinuxOptions"},
		},
		{
			name:       "rejects pod disallowed SELinux type",
			podSpec:    podSpec(withPodSELinux("", "", "spc_t")),
			wantChecks: []string{"SELinuxOptions"},
		},
		{
			name:       "rejects container custom SELinux user",
			podSpec:    podSpec(withContainerSELinux("custom_u", "", "")),
			wantChecks: []string{"SELinuxOptions"},
		},
		{
			name:       "rejects container custom SELinux role",
			podSpec:    podSpec(withContainerSELinux("", "custom_r", "")),
			wantChecks: []string{"SELinuxOptions"},
		},
		{
			name:       "rejects container disallowed SELinux type",
			podSpec:    podSpec(withContainerSELinux("", "", "spc_t")),
			wantChecks: []string{"SELinuxOptions"},
		},
		{
			name:       "rejects pod seccomp Unconfined",
			podSpec:    podSpec(withPodSeccomp(corev1.SeccompProfileTypeUnconfined)),
			wantChecks: []string{"SeccompProfile"},
		},
		{
			name:       "rejects container seccomp Unconfined",
			podSpec:    podSpec(withContainerSeccomp(corev1.SeccompProfileTypeUnconfined)),
			wantChecks: []string{"SeccompProfile"},
		},
		{
			name:       "rejects pod AppArmor Unconfined",
			podSpec:    podSpec(withPodAppArmor(corev1.AppArmorProfileTypeUnconfined)),
			wantChecks: []string{"AppArmorProfile"},
		},
		{
			name:       "rejects container AppArmor Unconfined",
			podSpec:    podSpec(withContainerAppArmor(corev1.AppArmorProfileTypeUnconfined)),
			wantChecks: []string{"AppArmorProfile"},
		},
		{
			name:       "rejects pod HostProcess true",
			podSpec:    podSpec(withPodHostProcess(true)),
			wantChecks: []string{"HostProcess"},
		},
		{
			name:       "rejects container HostProcess true",
			podSpec:    podSpec(withContainerHostProcess(true)),
			wantChecks: []string{"HostProcess"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := Evaluate(tt.podSpec, Baseline)
			gotMap := checksFromViolations(violations)
			for _, check := range tt.wantChecks {
				if !gotMap[check] {
					t.Errorf("Evaluate(Baseline) missing expected check %q, got: %+v", check, violations)
				}
			}
		})
	}
}

func TestEvaluate_BaselineAllowed(t *testing.T) {
	// Features that are permitted under Baseline should produce 0 Baseline violations
	t.Run("allowed capabilities", func(t *testing.T) {
		ps := podSpec(
			withCapAdd("NET_BIND_SERVICE", "CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID"),
		)
		violations := Evaluate(ps, Baseline)
		if len(violations) != 0 {
			t.Errorf("expected 0 Baseline violations for allowed caps, got: %+v", violations)
		}
	})

	t.Run("allowed sysctls", func(t *testing.T) {
		ps := podSpec(
			withSysctl("kernel.shm_rmid_forced", "1"),
			withSysctl("net.ipv4.ip_local_port_range", "1024 65535"),
			withSysctl("net.ipv4.ip_local_reserved_ports", "1024-4999"),
			withSysctl("net.ipv4.tcp_syncookies", "1"),
			withSysctl("net.ipv4.tcp_keepalive_time", "600"),
			withSysctl("net.ipv4.tcp_fin_timeout", "30"),
			withSysctl("net.ipv4.tcp_keepalive_intvl", "30"),
			withSysctl("net.ipv4.tcp_keepalive_probes", "5"),
		)
		violations := Evaluate(ps, Baseline)
		if len(violations) != 0 {
			t.Errorf("expected 0 Baseline violations for safe sysctls, got: %+v", violations)
		}
	})

	t.Run("allowed SELinux types", func(t *testing.T) {
		ps := podSpec(
			withContainerSELinux("", "", "container_t"),
		)
		violations := Evaluate(ps, Baseline)
		if len(violations) != 0 {
			t.Errorf("expected 0 Baseline violations for container_t, got: %+v", violations)
		}
	})

	t.Run("default procMount", func(t *testing.T) {
		ps := podSpec(withProcMount(corev1.DefaultProcMount))
		violations := Evaluate(ps, Baseline)
		if len(violations) != 0 {
			t.Errorf("expected 0 Baseline violations for Default procMount, got: %+v", violations)
		}
	})
}

func TestEvaluate_RestrictedChecks(t *testing.T) {
	tests := []struct {
		name       string
		podSpec    corev1.PodSpec
		wantChecks []string
	}{
		{
			name:       "requires drop ALL capabilities",
			podSpec:    podSpec(), // default has no securityContext
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects cap add other than NET_BIND_SERVICE under Restricted",
			podSpec:    podSpec(withDropAll, withCapAdd("CHOWN")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects lowercase drop all under Restricted",
			podSpec:    podSpec(withCapDrop("all")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects whitespace padded drop ALL under Restricted",
			podSpec:    podSpec(withCapDrop(" ALL ")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects lowercase add net_bind_service under Restricted",
			podSpec:    podSpec(withDropAll, withCapAdd("net_bind_service")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name:       "rejects whitespace padded add NET_BIND_SERVICE under Restricted",
			podSpec:    podSpec(withDropAll, withCapAdd(" NET_BIND_SERVICE ")),
			wantChecks: []string{"Capabilities"},
		},
		{
			name: "rejects non-allowed volume type (NFS)",
			podSpec: podSpec(withVolume("nfs-vol", corev1.VolumeSource{
				NFS: &corev1.NFSVolumeSource{Server: "1.2.3.4", Path: "/data"},
			})),
			wantChecks: []string{"Volumes"},
		},
		{
			name: "rejects non-allowed volume type (Image)",
			podSpec: podSpec(withVolume("img-vol", corev1.VolumeSource{
				Image: &corev1.ImageVolumeSource{Reference: "repo/img:v1"},
			})),
			wantChecks: []string{"Volumes"},
		},
		{
			name:       "rejects missing allowPrivilegeEscalation",
			podSpec:    podSpec(),
			wantChecks: []string{"AllowPrivilegeEscalation"},
		},
		{
			name:       "rejects allowPrivilegeEscalation true",
			podSpec:    podSpec(withAllowPrivilegeEscalation(true)),
			wantChecks: []string{"AllowPrivilegeEscalation"},
		},
		{
			name:       "rejects missing runAsNonRoot",
			podSpec:    podSpec(),
			wantChecks: []string{"RunAsNonRoot"},
		},
		{
			name:       "rejects runAsNonRoot false",
			podSpec:    podSpec(withContainerRunAsNonRoot(false)),
			wantChecks: []string{"RunAsNonRoot"},
		},
		{
			name:       "rejects pod runAsNonRoot false",
			podSpec:    podSpec(withPodRunAsNonRoot(false)),
			wantChecks: []string{"RunAsNonRoot"},
		},
		{
			name:       "rejects container runAsUser 0",
			podSpec:    podSpec(withContainerRunAsUser(0)),
			wantChecks: []string{"RunAsUser"},
		},
		{
			name:       "rejects pod runAsUser 0",
			podSpec:    podSpec(withPodRunAsUser(0)),
			wantChecks: []string{"RunAsUser"},
		},
		{
			name:       "requires seccomp profile",
			podSpec:    podSpec(),
			wantChecks: []string{"SeccompProfile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := Evaluate(tt.podSpec, Restricted)
			gotMap := checksFromViolations(violations)
			for _, check := range tt.wantChecks {
				if !gotMap[check] {
					t.Errorf("Evaluate(Restricted) missing expected check %q, got: %+v", check, violations)
				}
			}
		})
	}
}

func TestEvaluate_FullyCompliantRestrictedPod(t *testing.T) {
	ps := compliantRestrictedPod()
	// Add allowed volume types
	ps.Volumes = []corev1.Volume{
		{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
		{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{}}},
		{Name: "dir", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "pvc", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{}}},
		{Name: "csi", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "test"}}},
		{Name: "dapi", VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{}}},
		{Name: "proj", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}}},
		{Name: "eph", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}},
	}

	violations := Evaluate(ps, Restricted)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for fully compliant Restricted pod, got: %+v", violations)
	}

	if pass := PassesAt(ps); pass != Restricted {
		t.Errorf("PassesAt(compliantPod) = %v, want %v", pass, Restricted)
	}
}

func TestEvaluate_RestrictedAllowsNetBindService(t *testing.T) {
	ps := compliantRestrictedPod()
	// Adding NET_BIND_SERVICE is explicitly allowed by PSS Restricted
	ps.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}

	violations := Evaluate(ps, Restricted)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations when adding NET_BIND_SERVICE with drop ALL, got: %+v", violations)
	}
}

func TestEvaluate_PodLevelInheritance(t *testing.T) {
	t.Run("pod-level RunAsNonRoot satisfies container", func(t *testing.T) {
		ps := compliantRestrictedPod()
		// Pod level has RunAsNonRoot: true; container has it unset
		ps.Containers[0].SecurityContext.RunAsNonRoot = nil
		violations := Evaluate(ps, Restricted)
		gotMap := checksFromViolations(violations)
		if gotMap["RunAsNonRoot"] {
			t.Errorf("expected pod-level runAsNonRoot to satisfy check, got RunAsNonRoot violation")
		}
	})

	t.Run("container-level RunAsNonRoot false overrides pod-level true", func(t *testing.T) {
		ps := compliantRestrictedPod()
		f := false
		ps.Containers[0].SecurityContext.RunAsNonRoot = &f
		violations := Evaluate(ps, Restricted)
		gotMap := checksFromViolations(violations)
		if !gotMap["RunAsNonRoot"] {
			t.Errorf("expected container-level runAsNonRoot=false to override pod-level true")
		}
	})

	t.Run("pod-level RunAsUser 0 rejected even when container specifies non-zero", func(t *testing.T) {
		ps := compliantRestrictedPod()
		zero := int64(0)
		nonZero := int64(1000)
		ps.SecurityContext.RunAsUser = &zero
		ps.Containers[0].SecurityContext.RunAsUser = &nonZero
		violations := Evaluate(ps, Restricted)
		gotMap := checksFromViolations(violations)
		if !gotMap["RunAsUser"] {
			t.Errorf("expected pod-level runAsUser=0 to trigger violation even if container specifies non-zero")
		}
	})

	t.Run("pod-level seccomp profile satisfies container", func(t *testing.T) {
		ps := compliantRestrictedPod()
		ps.Containers[0].SecurityContext.SeccompProfile = nil
		violations := Evaluate(ps, Restricted)
		gotMap := checksFromViolations(violations)
		if gotMap["SeccompProfile"] {
			t.Errorf("expected pod-level seccomp to satisfy container")
		}
	})

	t.Run("container-level seccomp unconfined overrides pod runtime default", func(t *testing.T) {
		ps := compliantRestrictedPod()
		ps.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeUnconfined,
		}
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["SeccompProfile"] {
			t.Errorf("expected container unconfined seccomp to trigger Baseline violation")
		}
	})

	t.Run("explicit pod-level runAsNonRoot false rejects even when container sets true", func(t *testing.T) {
		ps := compliantRestrictedPod()
		f := false
		tr := true
		ps.SecurityContext.RunAsNonRoot = &f
		ps.Containers[0].SecurityContext.RunAsNonRoot = &tr
		violations := Evaluate(ps, Restricted)
		gotMap := checksFromViolations(violations)
		if !gotMap["RunAsNonRoot"] {
			t.Errorf("expected explicit pod-level runAsNonRoot=false to trigger violation even if container is true")
		}
	})

	t.Run("pod-level seccomp unconfined triggers Baseline violation even if container is RuntimeDefault", func(t *testing.T) {
		ps := compliantRestrictedPod()
		ps.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeUnconfined,
		}
		ps.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		}
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["SeccompProfile"] {
			t.Errorf("expected pod-level seccomp Unconfined to trigger Baseline violation")
		}
	})

	t.Run("pod-level AppArmor unconfined triggers Baseline violation even if container is RuntimeDefault", func(t *testing.T) {
		ps := compliantRestrictedPod()
		ps.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
			Type: corev1.AppArmorProfileTypeUnconfined,
		}
		ps.Containers[0].SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
			Type: corev1.AppArmorProfileTypeRuntimeDefault,
		}
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["AppArmorProfile"] {
			t.Errorf("expected pod-level AppArmor Unconfined to trigger Baseline violation")
		}
	})
}

func TestEvaluate_InitAndEphemeralContainers(t *testing.T) {
	t.Run("init container privileged triggers Baseline violation", func(t *testing.T) {
		ps := podSpec()
		tr := true
		ps.InitContainers = []corev1.Container{
			{
				Name: "init-setup",
				SecurityContext: &corev1.SecurityContext{
					Privileged: &tr,
				},
			},
		}
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["Privileged"] {
			t.Errorf("expected initContainer Privileged violation, got: %+v", violations)
		}
		found := false
		for _, v := range violations {
			if v.Container == "init-setup" && v.ContainerType == "initContainer" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected violation attributed to initContainer init-setup, got: %+v", violations)
		}
	})

	t.Run("ephemeral container triggers violation", func(t *testing.T) {
		ps := podSpec()
		tr := true
		ps.EphemeralContainers = []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: "debugger",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &tr,
					},
				},
			},
		}
		violations := Evaluate(ps, Baseline)
		found := false
		for _, v := range violations {
			if v.Container == "debugger" && v.ContainerType == "ephemeralContainer" && v.Check == "Privileged" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected violation attributed to ephemeralContainer debugger, got: %+v", violations)
		}
	})

	t.Run("init container HostProcess triggers Baseline violation", func(t *testing.T) {
		ps := podSpec()
		tr := true
		ps.InitContainers = []corev1.Container{
			{
				Name: "init-setup",
				SecurityContext: &corev1.SecurityContext{
					WindowsOptions: &corev1.WindowsSecurityContextOptions{
						HostProcess: &tr,
					},
				},
			},
		}
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["HostProcess"] {
			t.Errorf("expected initContainer HostProcess violation, got: %+v", violations)
		}
	})

	t.Run("ephemeral container HostProcess triggers Baseline violation", func(t *testing.T) {
		ps := podSpec()
		tr := true
		ps.EphemeralContainers = []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: "debugger",
					SecurityContext: &corev1.SecurityContext{
						WindowsOptions: &corev1.WindowsSecurityContextOptions{
							HostProcess: &tr,
						},
					},
				},
			},
		}
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["HostProcess"] {
			t.Errorf("expected ephemeralContainer HostProcess violation, got: %+v", violations)
		}
	})
}

func TestEvaluate_WindowsExemption(t *testing.T) {
	t.Run("windows pod exempts Linux-specific Restricted checks", func(t *testing.T) {
		// A Windows pod with runAsNonRoot: true, but no drop ALL, no seccomp, no allowPrivilegeEscalation: false
		tr := true
		ps := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &tr,
			},
			Containers: []corev1.Container{
				{
					Name: "win-app",
				},
			},
		}
		withPodOS(corev1.Windows)(&ps)

		violations := Evaluate(ps, Restricted)
		gotMap := checksFromViolations(violations)
		if gotMap["Capabilities"] {
			t.Errorf("expected Windows pod to exempt Restricted Capabilities check")
		}
		if gotMap["SeccompProfile"] {
			t.Errorf("expected Windows pod to exempt Restricted SeccompProfile check")
		}
		if gotMap["AllowPrivilegeEscalation"] {
			t.Errorf("expected Windows pod to exempt Restricted AllowPrivilegeEscalation check")
		}
		if len(violations) != 0 {
			t.Errorf("expected 0 Restricted violations for compliant Windows pod, got: %+v", violations)
		}
		if pass := PassesAt(ps); pass != Restricted {
			t.Errorf("PassesAt(windowsPod) = %v, want %v", pass, Restricted)
		}
	})

	t.Run("windows pod still enforces Baseline checks", func(t *testing.T) {
		tr := true
		ps := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				WindowsOptions: &corev1.WindowsSecurityContextOptions{
					HostProcess: &tr,
				},
			},
			Containers: []corev1.Container{
				{
					Name: "win-app",
				},
			},
		}
		withPodOS(corev1.Windows)(&ps)
		violations := Evaluate(ps, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["HostProcess"] {
			t.Errorf("expected Windows pod to enforce Baseline HostProcess check")
		}
	})
}

func TestPassesAt(t *testing.T) {
	tests := []struct {
		name     string
		podSpec  corev1.PodSpec
		wantPass Level
	}{
		{
			name:     "violates baseline -> passes at Privileged",
			podSpec:  podSpec(withHostNetwork),
			wantPass: Privileged,
		},
		{
			name:     "passes baseline, violates restricted -> passes at Baseline",
			podSpec:  podSpec(), // default empty container violates restricted runAsNonRoot, etc.
			wantPass: Baseline,
		},
		{
			name:     "fully compliant -> passes at Restricted",
			podSpec:  compliantRestrictedPod(),
			wantPass: Restricted,
		},
		{
			name: "compliant restricted pod with image volume -> passes at Baseline",
			podSpec: func() corev1.PodSpec {
				ps := compliantRestrictedPod()
				ps.Volumes = append(ps.Volumes, corev1.Volume{
					Name: "img-vol",
					VolumeSource: corev1.VolumeSource{
						Image: &corev1.ImageVolumeSource{Reference: "repo/img:v1"},
					},
				})
				return ps
			}(),
			wantPass: Baseline,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PassesAt(tt.podSpec)
			if got != tt.wantPass {
				t.Errorf("PassesAt() = %v, want %v", got, tt.wantPass)
			}
		})
	}
}

func TestLevel_StringAndParse(t *testing.T) {
	tests := []struct {
		level Level
		str   string
	}{
		{Privileged, "Privileged"},
		{Baseline, "Baseline"},
		{Restricted, "Restricted"},
		{Level(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.str {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.str)
		}
	}

	parseTests := []struct {
		input  string
		want   Level
		wantOk bool
	}{
		{"Privileged", Privileged, true},
		{"privileged", Privileged, true},
		{"BASELINE", Baseline, true},
		{"Restricted", Restricted, true},
		{" restricted ", Restricted, true},
		{"unknown", Privileged, false},
		{"", Privileged, false},
	}

	for _, tt := range parseTests {
		got, ok := ParseLevel(tt.input)
		if ok != tt.wantOk || got != tt.want {
			t.Errorf("ParseLevel(%q) = (%v, %v), want (%v, %v)", tt.input, got, ok, tt.want, tt.wantOk)
		}
	}
}

func TestEvaluateWithAnnotations_LegacyAppArmor(t *testing.T) {
	t.Run("legacy unconfined annotation triggers Baseline violation", func(t *testing.T) {
		ps := podSpec()
		ps.Containers[0].Name = "app"
		annots := map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
		}
		violations := EvaluateWithAnnotations(ps, annots, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["AppArmorProfile"] {
			t.Errorf("expected legacy AppArmor unconfined annotation to trigger Baseline violation, got: %+v", violations)
		}
		if pass := PassesAtWithAnnotations(ps, annots); pass != Privileged {
			t.Errorf("PassesAtWithAnnotations = %v, want Privileged", pass)
		}
	})

	t.Run("legacy runtime/default annotation passes Baseline", func(t *testing.T) {
		ps := podSpec()
		ps.Containers[0].Name = "app"
		annots := map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "runtime/default",
		}
		violations := EvaluateWithAnnotations(ps, annots, Baseline)
		gotMap := checksFromViolations(violations)
		if gotMap["AppArmorProfile"] {
			t.Errorf("expected legacy runtime/default annotation not to trigger violation, got: %+v", violations)
		}
	})

	t.Run("forbidden legacy annotation triggers violation even if container specifies structured RuntimeDefault", func(t *testing.T) {
		ps := podSpec()
		ps.Containers[0].Name = "app"
		ps.Containers[0].SecurityContext = &corev1.SecurityContext{
			AppArmorProfile: &corev1.AppArmorProfile{
				Type: corev1.AppArmorProfileTypeRuntimeDefault,
			},
		}
		// Annotation says unconfined, and structured field is RuntimeDefault -> both are checked independently
		annots := map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
		}
		violations := EvaluateWithAnnotations(ps, annots, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["AppArmorProfile"] {
			t.Errorf("expected legacy AppArmor annotation to be evaluated independently of structured profile, got: %+v", violations)
		}
		if pass := PassesAtWithAnnotations(ps, annots); pass != Privileged {
			t.Errorf("PassesAtWithAnnotations = %v, want Privileged", pass)
		}
	})

	t.Run("stale annotation for absent container triggers Baseline violation", func(t *testing.T) {
		ps := podSpec()
		ps.Containers[0].Name = "app"
		annots := map[string]string{
			"container.apparmor.security.beta.kubernetes.io/absent-container": "unconfined",
		}
		violations := EvaluateWithAnnotations(ps, annots, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["AppArmorProfile"] {
			t.Errorf("expected stale legacy annotation for absent container to trigger Baseline violation, got: %+v", violations)
		}
	})

	t.Run("forbidden annotation value like docker/default triggers Baseline violation", func(t *testing.T) {
		ps := podSpec()
		ps.Containers[0].Name = "app"
		annots := map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "docker/default",
		}
		violations := EvaluateWithAnnotations(ps, annots, Baseline)
		gotMap := checksFromViolations(violations)
		if !gotMap["AppArmorProfile"] {
			t.Errorf("expected docker/default legacy annotation to trigger Baseline violation, got: %+v", violations)
		}
	})

	t.Run("allowed localhost/* legacy annotation passes Baseline", func(t *testing.T) {
		ps := podSpec()
		ps.Containers[0].Name = "app"
		annots := map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "localhost/custom-profile",
		}
		violations := EvaluateWithAnnotations(ps, annots, Baseline)
		gotMap := checksFromViolations(violations)
		if gotMap["AppArmorProfile"] {
			t.Errorf("expected localhost/* legacy annotation not to trigger violation, got: %+v", violations)
		}
	})
}
