package pss

import (
	"reflect"
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
// rejects, for example, a Windows pod that sets Linux-only fields or a
// negative hostPort, so the evaluators are not expected to agree on such a pod.
//
// TestParityCorpusWitnessesEveryPolicyRevision keeps the corpus itself from
// falling behind: every upstream check, and every revision of one, has to
// change the verdict of at least one pod below.

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

	cases := []parityCase{
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

		// Volumes. parityVolumeCases adds one case for every source type.
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

		// Boundaries of the lists and ranges the standards define. The
		// capabilities Baseline allows are generated by parityCapabilityCases.
		{"hostPort 1", func(p *corev1.Pod) {
			main(p).Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 1}}
		}},
		{"hostPort 65535", func(p *corev1.Pod) {
			main(p).Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 65535}}
		}},
		{"hostPort on the second port only", func(p *corev1.Pod) {
			main(p).Ports = []corev1.ContainerPort{{ContainerPort: 80}, {ContainerPort: 81, HostPort: 8081}}
		}},
		{"privileged false", func(p *corev1.Pod) { main(p).SecurityContext.Privileged = parityPtr(false) }},
		{"probe host 127.0.0.1", func(p *corev1.Pod) { main(p).LivenessProbe = httpProbe("127.0.0.1") }},
		{"liveness tcpSocket host", func(p *corev1.Pod) { main(p).LivenessProbe = tcpProbe("10.0.0.1") }},
		{"readiness httpGet host", func(p *corev1.Pod) { main(p).ReadinessProbe = httpProbe("10.0.0.1") }},
		{"startup tcpSocket host", func(p *corev1.Pod) { main(p).StartupProbe = tcpProbe("10.0.0.1") }},
		{"postStart tcpSocket host", func(p *corev1.Pod) {
			main(p).Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
				TCPSocket: &corev1.TCPSocketAction{Host: "10.0.0.1", Port: intstr.FromInt32(22)},
			}}
		}},
		{"preStop httpGet host", func(p *corev1.Pod) {
			main(p).Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{Host: "10.0.0.1", Port: intstr.FromInt32(80)},
			}}
		}},
		{"grpc probe", func(p *corev1.Pod) {
			main(p).LivenessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 80}}}
		}},
		{"safe and unsafe sysctl", func(p *corev1.Pod) {
			p.Spec.SecurityContext.Sysctls = []corev1.Sysctl{
				{Name: "kernel.shm_rmid_forced", Value: "1"}, {Name: "kernel.msgmax", Value: "1"},
			}
		}},
		{"two safe sysctls", func(p *corev1.Pod) {
			p.Spec.SecurityContext.Sysctls = []corev1.Sysctl{
				{Name: "kernel.shm_rmid_forced", Value: "1"}, {Name: "net.ipv4.tcp_syncookies", Value: "1"},
			}
		}},
		{"drop NET_RAW and ALL", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Drop = []corev1.Capability{"NET_RAW", "ALL"}
		}},
		{"add NET_BIND_SERVICE and CHOWN", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE", "CHOWN"}
		}},
		{"add CHOWN and SYS_ADMIN", func(p *corev1.Pod) {
			main(p).SecurityContext.Capabilities.Add = []corev1.Capability{"CHOWN", "SYS_ADMIN"}
		}},
		{"capabilities empty", func(p *corev1.Pod) { main(p).SecurityContext.Capabilities = &corev1.Capabilities{} }},
		{"selinux type container_init_t", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "container_init_t"}
		}},
		{"selinux type container_kvm_t", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "container_kvm_t"}
		}},
		{"selinux pod type spc_t", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "spc_t"}
		}},
		{"selinux pod role", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Role: "system_r"}
		}},
		{"selinux container user", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{User: "system_u"}
		}},
		{"selinux allowed type with user", func(p *corev1.Pod) {
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "container_t", User: "system_u"}
		}},
		{"selinux empty options", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{}
			main(p).SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{}
		}},
		{"seccomp pod Localhost", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: parityPtr("profile.json"),
			}
		}},
		{"seccomp unset on pod, set on main only", func(p *corev1.Pod) {
			p.Spec.SecurityContext.SeccompProfile = nil
			main(p).SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}},
		// The seccomp annotations stopped being part of the policy in v1.19.
		{"seccomp annotations unconfined", func(p *corev1.Pod) {
			p.Annotations = map[string]string{
				"seccomp.security.alpha.kubernetes.io/pod":            "unconfined",
				"container.seccomp.security.alpha.kubernetes.io/main": "unconfined",
			}
		}},
		{"apparmor pod Localhost", func(p *corev1.Pod) {
			p.Spec.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
				Type: corev1.AppArmorProfileTypeLocalhost, LocalhostProfile: parityPtr("profile"),
			}
		}},
		{"apparmor annotation empty", func(p *corev1.Pod) {
			p.Annotations = map[string]string{appArmorAnnotationPrefix + "main": ""}
		}},
		{"apparmor annotation unconfined on init container", func(p *corev1.Pod) {
			p.Annotations = map[string]string{appArmorAnnotationPrefix + "init": "unconfined"}
		}},
		{"runAsNonRoot unset on pod, true on main only", func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsNonRoot = nil
			main(p).SecurityContext.RunAsNonRoot = parityPtr(true)
		}},
		{"runAsUser 1 on container", func(p *corev1.Pod) { main(p).SecurityContext.RunAsUser = parityPtr(int64(1)) }},
		{"user namespace, runAsUser 0 on container", userNamespace(func(p *corev1.Pod) {
			main(p).SecurityContext.RunAsUser = parityPtr(int64(0))
		})},
		{"second container without a security context", func(p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "second", Image: "image"})
		}},
		{"windows pod, hostPath volume", func(p *corev1.Pod) {
			p.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
			p.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: parityPtr(true)}
			p.Spec.InitContainers = nil
			main(p).SecurityContext = nil
			p.Spec.Volumes = []corev1.Volume{{Name: "vol", VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: `C:\`},
			}}}
		}},
	}

	cases = append(cases, parityVolumeCases()...)
	cases = append(cases, parityCapabilityCases()...)
	cases = append(cases, parityContainerKindCases()...)
	return cases
}

// parityVolumeCases returns one case per volume source type, read off
// corev1.VolumeSource so that a source added to the API joins the corpus when
// k8s.io/api is bumped. The sources are left empty, which pod validation
// would not accept for most of them, because both evaluators look only at
// which source is set; the cases above carry filled-in sources.
func parityVolumeCases() []parityCase {
	var cases []parityCase
	sources := reflect.TypeFor[corev1.VolumeSource]()
	for i := range sources.NumField() {
		field := sources.Field(i)
		if field.Type.Kind() != reflect.Pointer {
			continue
		}
		cases = append(cases, parityCase{"volume source " + field.Name, func(p *corev1.Pod) {
			var src corev1.VolumeSource
			reflect.ValueOf(&src).Elem().Field(i).Set(reflect.New(field.Type.Elem()))
			p.Spec.Volumes = []corev1.Volume{{Name: "vol", VolumeSource: src}}
		}})
	}
	return cases
}

// parityCapabilityCases adds each capability on its own: the ones Baseline
// allows and a few it does not. The names are written out here rather than
// taken from baselineAllowedCapabilities, so dropping one from that set fails.
func parityCapabilityCases() []parityCase {
	var cases []parityCase
	for _, capability := range []corev1.Capability{
		"AUDIT_WRITE", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
		"SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
		"ALL", "NET_ADMIN", "NET_RAW", "SYS_MODULE", "SYS_PTRACE", "chown",
	} {
		cases = append(cases, parityCase{"add " + string(capability), func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{capability}
		}})
	}
	return cases
}

// parityContainerKindCases applies each container-scoped mutation to the init
// container and to an ephemeral container; the cases above apply them to the
// main container. The standards restrict all three alike.
func parityContainerKindCases() []parityCase {
	mutations := []struct {
		name   string
		mutate func(*corev1.Container)
	}{
		{"privileged", func(c *corev1.Container) { c.SecurityContext.Privileged = parityPtr(true) }},
		{"add SYS_ADMIN", func(c *corev1.Container) {
			c.SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		}},
		{"capabilities unset", func(c *corev1.Container) { c.SecurityContext.Capabilities = nil }},
		{"procMount Unmasked", func(c *corev1.Container) {
			c.SecurityContext.ProcMount = parityPtr(corev1.UnmaskedProcMount)
		}},
		{"selinux type spc_t", func(c *corev1.Container) {
			c.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "spc_t"}
		}},
		{"seccomp Unconfined", func(c *corev1.Container) {
			c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}},
		{"apparmor Unconfined", func(c *corev1.Container) {
			c.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		}},
		{"allowPrivilegeEscalation true", func(c *corev1.Container) {
			c.SecurityContext.AllowPrivilegeEscalation = parityPtr(true)
		}},
		{"runAsNonRoot false", func(c *corev1.Container) { c.SecurityContext.RunAsNonRoot = parityPtr(false) }},
		{"runAsUser 0", func(c *corev1.Container) { c.SecurityContext.RunAsUser = parityPtr(int64(0)) }},
		{"no security context", func(c *corev1.Container) { c.SecurityContext = nil }},
	}

	var cases []parityCase
	for _, m := range mutations {
		cases = append(cases,
			parityCase{"init container: " + m.name, func(p *corev1.Pod) { m.mutate(&p.Spec.InitContainers[0]) }},
			parityCase{"ephemeral container: " + m.name, func(p *corev1.Pod) {
				p.Spec.EphemeralContainers = []corev1.EphemeralContainer{parityEphemeralContainer()}
				m.mutate((*corev1.Container)(&p.Spec.EphemeralContainers[0].EphemeralContainerCommon))
			}},
		)
	}
	// With no profile on the pod, an ephemeral container needs its own.
	cases = append(cases, parityCase{"ephemeral container: seccomp unset, pod unset", func(p *corev1.Pod) {
		p.Spec.SecurityContext.SeccompProfile = nil
		for _, c := range []*corev1.Container{&p.Spec.InitContainers[0], &p.Spec.Containers[0]} {
			c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{parityEphemeralContainer()}
	}})
	return cases
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

// TestParityCorpusWitnessesEveryPolicyRevision checks the corpus against the
// upstream policy, not this package. The parity test can only catch drift on
// pods it evaluates: when a pod-security-admission bump adds a check or revises
// one, PolicyVersion has to follow, but nothing would compare the new rule
// unless a case happens to exercise it. So every upstream check must reject
// some pod of the corpus, and every revision of a check must disagree with the
// revision before it on some pod. A bump that fails here needs a new case in
// parityCases. One witness per revision is a floor, not full coverage of it.
//
// This assumes a revision changes the verdict of some valid pod, which holds
// for every revision so far. One that only rewords a message, or only differs
// on pods the API server rejects, cannot be witnessed and would have to be
// exempted here by name.
func TestParityCorpusWitnessesEveryPolicyRevision(t *testing.T) {
	names := map[string]bool{}
	var pods []*corev1.Pod
	for _, tc := range parityCases() {
		if names[tc.name] {
			t.Errorf("duplicate case name %q", tc.name)
		}
		names[tc.name] = true
		pod := parityRestrictedPod()
		tc.mutate(pod)
		pods = append(pods, pod)
	}

	anyPod := func(matches func(*corev1.Pod) bool) bool {
		for _, pod := range pods {
			if matches(pod) {
				return true
			}
		}
		return false
	}

	for _, check := range policy.DefaultChecks() {
		revisions := check.Versions
		latest := revisions[len(revisions)-1]
		if !anyPod(func(pod *corev1.Pod) bool { return !latest.CheckPod(&pod.ObjectMeta, &pod.Spec).Allowed }) {
			t.Errorf("no case is rejected by the %s check", check.ID)
		}
		for i := 1; i < len(revisions); i++ {
			previous, revision := revisions[i-1], revisions[i]
			if !anyPod(func(pod *corev1.Pod) bool {
				return revision.CheckPod(&pod.ObjectMeta, &pod.Spec).Allowed !=
					previous.CheckPod(&pod.ObjectMeta, &pod.Spec).Allowed
			}) {
				t.Errorf("no case gets a different verdict from the %s and %s revisions of the %s check",
					previous.MinimumVersion.String(), revision.MinimumVersion.String(), check.ID)
			}
		}
	}
}

// TestPolicyVersionMatchesPodSecurityAdmission keeps PolicyVersion equal to
// the newest policy revision the pinned pod-security-admission defines, which
// is what "latest" evaluates in the parity test above. Bumping the module to a
// release that revises a check fails here until PolicyVersion follows.
func TestPolicyVersionMatchesPodSecurityAdmission(t *testing.T) {
	var newest psaapi.Version
	for _, check := range policy.DefaultChecks() {
		for _, revision := range check.Versions {
			if newest.Older(revision.MinimumVersion) {
				newest = revision.MinimumVersion
			}
		}
	}

	if got := newest.String(); got != PolicyVersion {
		t.Errorf("PolicyVersion = %s, pod-security-admission's newest policy revision is %s", PolicyVersion, got)
	}
}
