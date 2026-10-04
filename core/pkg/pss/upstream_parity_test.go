package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

// The checks in this package are a hand-written copy of the Pod Security
// Standards, and the standards move: probe and lifecycle hosts became a
// Baseline restriction in v1.34, user-namespace pods were relaxed in v1.35,
// and the safe sysctl set grows every few releases. A copy that is not
// compared against the reference drifts silently in both directions -- it
// passes pods the API server rejects, and it rejects pods the API server
// admits.
//
// TestParityWithPodSecurityAdmission compares the verdict of this package
// with k8s.io/pod-security-admission, the evaluator the API server itself
// runs, at its latest policy version. The upstream module is imported by
// tests only; it is not linked into the kubescape binary.
//
// The corpus is limited to pods the API server accepts. Pod validation
// rejects, for example, a Windows pod that sets Linux-only fields, so the
// evaluators are not expected to agree on such a pod.

func parityPtr[T any](v T) *T { return &v }

// parityRestrictedPod is a pod that satisfies the Restricted level; every case
// below is one mutation away from it.
func parityRestrictedPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   parityPtr(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: []corev1.Container{{Name: "init", Image: "image", SecurityContext: parityRestrictedSecurityContext()}},
			Containers:     []corev1.Container{{Name: "main", Image: "image", SecurityContext: parityRestrictedSecurityContext()}},
		},
	}
}

func parityRestrictedSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: parityPtr(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

func parityEphemeralContainer() corev1.EphemeralContainer {
	return corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
		Name: "debug", Image: "image", SecurityContext: parityRestrictedSecurityContext(),
	}}
}

type parityCase struct {
	name   string
	mutate func(*corev1.Pod)
}

func parityCases() []parityCase {
	httpProbe := func(host string) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Host: host, Port: intstr.FromInt32(80)},
		}}
	}
	tcpProbe := func(host string) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{Host: host, Port: intstr.FromInt32(80)},
		}}
	}
	volume := func(src corev1.VolumeSource) func(*corev1.Pod) {
		return func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "vol", VolumeSource: src}}
		}
	}
	sysctl := func(name string) func(*corev1.Pod) {
		return func(p *corev1.Pod) {
			p.Spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: name, Value: "1"}}
		}
	}
	userNamespace := func(mutate func(*corev1.Pod)) func(*corev1.Pod) {
		return func(p *corev1.Pod) {
			p.Spec.HostUsers = parityPtr(false)
			mutate(p)
		}
	}
	main := func(p *corev1.Pod) *corev1.Container { return &p.Spec.Containers[0] }
	rootUser := func(p *corev1.Pod) {
		p.Spec.SecurityContext.RunAsNonRoot = nil
		p.Spec.SecurityContext.RunAsUser = parityPtr(int64(0))
	}
	unmaskedProc := func(p *corev1.Pod) {
		main(p).SecurityContext.ProcMount = parityPtr(corev1.UnmaskedProcMount)
	}

	return []parityCase{
		{"restricted pod", func(*corev1.Pod) {}},
		{"no security context", func(p *corev1.Pod) {
			p.Spec.SecurityContext = nil
			p.Spec.InitContainers = nil
			main(p).SecurityContext = nil
		}},

		// Host namespaces, ports and processes.
		{"hostNetwork", func(p *corev1.Pod) { p.Spec.HostNetwork = true }},
		{"hostPID", func(p *corev1.Pod) { p.Spec.HostPID = true }},
		{"hostIPC", func(p *corev1.Pod) { p.Spec.HostIPC = true }},
		{"hostPort", func(p *corev1.Pod) {
			main(p).Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080}}
		}},
		{"hostPort in init container", func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080}}
		}},
		{"containerPort only", func(p *corev1.Pod) {
			main(p).Ports = []corev1.ContainerPort{{ContainerPort: 80}}
		}},
		{"privileged", func(p *corev1.Pod) { main(p).SecurityContext.Privileged = parityPtr(true) }},
		{"privileged ephemeral container", func(p *corev1.Pod) {
			ec := parityEphemeralContainer()
			ec.SecurityContext.Privileged = parityPtr(true)
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{ec}
		}},
		{"pod hostProcess", func(p *corev1.Pod) {
			p.Spec.SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: parityPtr(true)}
		}},
		{"container hostProcess", func(p *corev1.Pod) {
			main(p).SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: parityPtr(true)}
		}},

		// Probe and lifecycle hosts (Baseline since v1.34).
		{"liveness httpGet host", func(p *corev1.Pod) { main(p).LivenessProbe = httpProbe("169.254.169.254") }},
		{"readiness tcpSocket host", func(p *corev1.Pod) { main(p).ReadinessProbe = tcpProbe("10.0.0.1") }},
		{"startup httpGet host", func(p *corev1.Pod) { main(p).StartupProbe = httpProbe("10.0.0.1") }},
		{"init container probe host", func(p *corev1.Pod) {
			p.Spec.InitContainers[0].StartupProbe = httpProbe("10.0.0.1")
		}},
		{"postStart httpGet host", func(p *corev1.Pod) {
			main(p).Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{Host: "10.0.0.1", Port: intstr.FromInt32(80)},
			}}
		}},
		{"preStop tcpSocket host", func(p *corev1.Pod) {
			main(p).Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				TCPSocket: &corev1.TCPSocketAction{Host: "10.0.0.1", Port: intstr.FromInt32(22)},
			}}
		}},
		{"ephemeral container probe host", func(p *corev1.Pod) {
			ec := parityEphemeralContainer()
			ec.ReadinessProbe = httpProbe("10.0.0.1")
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{ec}
		}},
		{"probe without host", func(p *corev1.Pod) {
			main(p).LivenessProbe = httpProbe("")
			main(p).ReadinessProbe = tcpProbe("")
			main(p).Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{Command: []string{"true"}},
			}}
		}},

		// Volumes.
		{"hostPath volume", volume(corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}})},
		{"nfs volume", volume(corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: "s", Path: "/"}})},
		{"emptyDir volume", volume(corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}})},
		{"configMap volume", volume(corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}})},
		{"secret volume", volume(corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "s"}})},
		{"projected volume", volume(corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}})},
		{"downwardAPI volume", volume(corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{}})},
		{"csi volume", volume(corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "d"}})},
		{"ephemeral volume", volume(corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}})},
		{"persistentVolumeClaim volume", volume(corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"},
		})},
		{"image volume", volume(corev1.VolumeSource{Image: &corev1.ImageVolumeSource{Reference: "image"}})},
		{"volume without a source", volume(corev1.VolumeSource{})},

		// Sysctls: the safe set as of each policy revision, plus unsafe ones.
		{"sysctl kernel.shm_rmid_forced", sysctl("kernel.shm_rmid_forced")},
		{"sysctl net.ipv4.ip_local_port_range", sysctl("net.ipv4.ip_local_port_range")},
		{"sysctl net.ipv4.tcp_syncookies", sysctl("net.ipv4.tcp_syncookies")},
		{"sysctl net.ipv4.ping_group_range", sysctl("net.ipv4.ping_group_range")},
		{"sysctl net.ipv4.ip_unprivileged_port_start", sysctl("net.ipv4.ip_unprivileged_port_start")},
		{"sysctl net.ipv4.ip_local_reserved_ports", sysctl("net.ipv4.ip_local_reserved_ports")},
		{"sysctl net.ipv4.tcp_keepalive_time", sysctl("net.ipv4.tcp_keepalive_time")},
		{"sysctl net.ipv4.tcp_fin_timeout", sysctl("net.ipv4.tcp_fin_timeout")},
		{"sysctl net.ipv4.tcp_keepalive_intvl", sysctl("net.ipv4.tcp_keepalive_intvl")},
		{"sysctl net.ipv4.tcp_keepalive_probes", sysctl("net.ipv4.tcp_keepalive_probes")},
		{"sysctl net.ipv4.tcp_rmem", sysctl("net.ipv4.tcp_rmem")},
		{"sysctl net.ipv4.tcp_wmem", sysctl("net.ipv4.tcp_wmem")},
		{"sysctl net.ipv4.tcp_slow_start_after_idle", sysctl("net.ipv4.tcp_slow_start_after_idle")},
		{"sysctl net.ipv4.tcp_notsent_lowat", sysctl("net.ipv4.tcp_notsent_lowat")},
		{"sysctl kernel.msgmax", sysctl("kernel.msgmax")},
		{"sysctl net.core.somaxconn", sysctl("net.core.somaxconn")},

		// Capabilities.
		{"add NET_BIND_SERVICE", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
		}},
		{"add CHOWN", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Add = []corev1.Capability{"CHOWN"}
		}},
		{"add SYS_ADMIN", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		}},
		{"add CAP_SYS_ADMIN", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Add = []corev1.Capability{"CAP_SYS_ADMIN"}
		}},
		{"drop lowercase all", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Drop = []corev1.Capability{"all"}
		}},
		{"drop only NET_RAW", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Drop = []corev1.Capability{"NET_RAW"}
		}},
		{"capabilities unset", func(p *corev1.Pod) { main(p).SecurityContext.Capabilities = nil }},

		// procMount.
		{"procMount Default", func(p *corev1.Pod) {
			main(p).SecurityContext.ProcMount = parityPtr(corev1.DefaultProcMount)
		}},
		{"procMount Unmasked", unmaskedProc},

		// SELinux.
		{"selinux type container_t", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "container_t"}
		}},
		{"selinux type container_engine_t", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "container_engine_t"}
		}},
		{"selinux type spc_t", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "spc_t"}
		}},
		{"selinux pod user", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{User: "system_u"}
		}},
		{"selinux container role", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Role: "system_r"}
		}},
		{"selinux level only", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Level: "s0:c1,c2"}
		}},

		// Seccomp.
		{"seccomp pod Unconfined", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}},
		{"seccomp container Unconfined", func(p *corev1.Pod) {
			main(p).SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}},
		{"seccomp pod Unconfined, containers RuntimeDefault", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
			for i := range p.Spec.InitContainers {
				p.Spec.InitContainers[i].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
			}
			main(p).SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}},
		{"seccomp unset", func(p *corev1.Pod) { p.Spec.SecurityContext.SeccompProfile = nil }},
		{"seccomp unset on pod, set on every container", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = nil
			p.Spec.InitContainers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
			main(p).SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: parityPtr("profile.json"),
			}
		}},
		{"seccomp container unknown type", func(p *corev1.Pod) {
			main(p).SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: "Bogus"}
		}},

		// AppArmor.
		{"apparmor pod RuntimeDefault", func(p *corev1.Pod) {
			p.Spec.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}
		}},
		{"apparmor container Localhost", func(p *corev1.Pod) {
			main(p).SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
				Type: corev1.AppArmorProfileTypeLocalhost, LocalhostProfile: parityPtr("profile"),
			}
		}},
		{"apparmor pod Unconfined", func(p *corev1.Pod) {
			p.Spec.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		}},
		{"apparmor container Unconfined", func(p *corev1.Pod) {
			main(p).SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		}},
		{"apparmor pod unknown type", func(p *corev1.Pod) {
			p.Spec.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: "Bogus"}
		}},
		{"apparmor container unknown type", func(p *corev1.Pod) {
			main(p).SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: "Bogus"}
		}},
		{"apparmor pod Unconfined, containers RuntimeDefault", func(p *corev1.Pod) {
			p.Spec.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
			p.Spec.InitContainers[0].SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}
			main(p).SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}
		}},
		{"apparmor annotation runtime/default", func(p *corev1.Pod) {
			p.Annotations = map[string]string{appArmorAnnotationPrefix + "main": "runtime/default"}
		}},
		{"apparmor annotation localhost", func(p *corev1.Pod) {
			p.Annotations = map[string]string{appArmorAnnotationPrefix + "main": "localhost/profile"}
		}},
		{"apparmor annotation unconfined", func(p *corev1.Pod) {
			p.Annotations = map[string]string{appArmorAnnotationPrefix + "main": "unconfined"}
		}},

		// Privilege escalation and users.
		{"allowPrivilegeEscalation true", func(p *corev1.Pod) {
			main(p).SecurityContext.AllowPrivilegeEscalation = parityPtr(true)
		}},
		{"allowPrivilegeEscalation unset", func(p *corev1.Pod) {
			main(p).SecurityContext.AllowPrivilegeEscalation = nil
		}},
		{"runAsNonRoot unset", func(p *corev1.Pod) { p.Spec.SecurityContext.RunAsNonRoot = nil }},
		{"runAsNonRoot false on pod", func(p *corev1.Pod) { p.Spec.SecurityContext.RunAsNonRoot = parityPtr(false) }},
		{"runAsNonRoot false on pod, true on containers", func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsNonRoot = parityPtr(false)
			p.Spec.InitContainers[0].SecurityContext.RunAsNonRoot = parityPtr(true)
			main(p).SecurityContext.RunAsNonRoot = parityPtr(true)
		}},
		{"runAsNonRoot false on container", func(p *corev1.Pod) {
			main(p).SecurityContext.RunAsNonRoot = parityPtr(false)
		}},
		{"runAsNonRoot only on containers", func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsNonRoot = nil
			p.Spec.InitContainers[0].SecurityContext.RunAsNonRoot = parityPtr(true)
			main(p).SecurityContext.RunAsNonRoot = parityPtr(true)
		}},
		{"runAsUser 0 on pod", func(p *corev1.Pod) { p.Spec.SecurityContext.RunAsUser = parityPtr(int64(0)) }},
		{"runAsUser 0 on container", func(p *corev1.Pod) { main(p).SecurityContext.RunAsUser = parityPtr(int64(0)) }},
		{"runAsUser 0 on pod, 1000 on containers", func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsUser = parityPtr(int64(0))
			p.Spec.InitContainers[0].SecurityContext.RunAsUser = parityPtr(int64(1000))
			main(p).SecurityContext.RunAsUser = parityPtr(int64(1000))
		}},
		{"runAsUser 1000", func(p *corev1.Pod) { p.Spec.SecurityContext.RunAsUser = parityPtr(int64(1000)) }},

		// User namespaces (hostUsers: false) relax the root and procMount
		// restrictions since v1.35; nothing else.
		{"user namespace", userNamespace(func(*corev1.Pod) {})},
		{"user namespace, root user", userNamespace(rootUser)},
		{"user namespace, runAsNonRoot false", userNamespace(func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsNonRoot = parityPtr(false)
		})},
		{"user namespace, runAsNonRoot unset", userNamespace(func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsNonRoot = nil
		})},
		{"user namespace, procMount Unmasked", userNamespace(unmaskedProc)},
		{"user namespace, privileged", userNamespace(func(p *corev1.Pod) {
			main(p).SecurityContext.Privileged = parityPtr(true)
		})},
		{"user namespace, capabilities unset", userNamespace(func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities = nil
		})},
		{"hostUsers true, root user", func(p *corev1.Pod) {
			p.Spec.HostUsers = parityPtr(true)
			rootUser(p)
		}},
		{"hostUsers true, procMount Unmasked", func(p *corev1.Pod) {
			p.Spec.HostUsers = parityPtr(true)
			unmaskedProc(p)
		}},

		// Windows pods are exempt from the Linux-only Restricted fields.
		{"windows pod", func(p *corev1.Pod) {
			p.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
			p.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: parityPtr(true)}
			p.Spec.InitContainers = nil
			main(p).SecurityContext = nil
		}},
		{"windows pod, runAsNonRoot unset", func(p *corev1.Pod) {
			p.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
			p.Spec.SecurityContext = nil
			p.Spec.InitContainers = nil
			main(p).SecurityContext = nil
		}},
		{"linux pod", func(p *corev1.Pod) { p.Spec.OS = &corev1.PodOS{Name: corev1.Linux} }},
	}
}

func TestParityWithPodSecurityAdmission(t *testing.T) {
	evaluator, err := policy.NewEvaluator(policy.DefaultChecks(), nil)
	if err != nil {
		t.Fatalf("building the upstream evaluator: %v", err)
	}

	levels := []struct {
		ours     Level
		upstream psaapi.Level
	}{
		{Baseline, psaapi.LevelBaseline},
		{Restricted, psaapi.LevelRestricted},
	}

	upstreamVerdict := func(pod *corev1.Pod, level psaapi.Level) policy.AggregateCheckResult {
		lv := psaapi.LevelVersion{Level: level, Version: psaapi.LatestVersion()}
		return policy.AggregateCheckResults(evaluator.EvaluatePod(lv, &pod.ObjectMeta, &pod.Spec))
	}

	for _, tc := range parityCases() {
		t.Run(tc.name, func(t *testing.T) {
			pod := parityRestrictedPod()
			tc.mutate(pod)

			wantPassesAt := Privileged
			for _, lvl := range levels {
				want := upstreamVerdict(pod, lvl.upstream)
				violations := EvaluateWithAnnotations(pod.Spec, pod.Annotations, lvl.ours)
				if got := len(violations) == 0; got != want.Allowed {
					t.Errorf("%s: allowed = %v, pod-security-admission says %v (%s)\nviolations: %+v",
						lvl.ours, got, want.Allowed, want.ForbiddenDetail(), violations)
				}
				if want.Allowed && wantPassesAt == lvl.ours-1 {
					wantPassesAt = lvl.ours
				}
			}

			if got := PassesAtWithAnnotations(pod.Spec, pod.Annotations); got != wantPassesAt {
				t.Errorf("PassesAt = %s, pod-security-admission admits the pod up to %s", got, wantPassesAt)
			}
		})
	}
}
