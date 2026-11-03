package clustercomponents

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconstructKernel(t *testing.T) {
	tests := []struct {
		name string
		in   KernelEvidence
		want KernelPackage
	}{
		{
			name: "amazon linux 2",
			in:   KernelEvidence{Release: "5.10.205-195.807.amzn2.x86_64", OSImage: "Amazon Linux 2"},
			want: KernelPackage{Distro: DistroAmazonLinux, DistroVersion: "2", Type: PackageTypeRPM, Name: "kernel", Version: "5.10.205-195.807.amzn2"},
		},
		{
			name: "amazon linux 2023 arm",
			in:   KernelEvidence{Release: "6.1.79-99.164.amzn2023.aarch64", OSImage: "Amazon Linux 2023.3.20240304"},
			want: KernelPackage{Distro: DistroAmazonLinux, DistroVersion: "2023", Type: PackageTypeRPM, Name: "kernel", Version: "6.1.79-99.164.amzn2023"},
		},
		{
			name: "amazon linux 2023 kernel 6.12",
			in:   KernelEvidence{Release: "6.12.20-28.97.amzn2023.x86_64", OSID: "amzn"},
			want: KernelPackage{Distro: DistroAmazonLinux, DistroVersion: "2023", Type: PackageTypeRPM, Name: "kernel6.12", Version: "6.12.20-28.97.amzn2023"},
		},
		{
			name: "rhel 9",
			in:   KernelEvidence{Release: "5.14.0-362.8.1.el9_3.x86_64", OSImage: "Red Hat Enterprise Linux 9.3 (Plow)"},
			want: KernelPackage{Distro: DistroRHEL, DistroVersion: "9", Type: PackageTypeRPM, Name: "kernel", Version: "5.14.0-362.8.1.el9_3"},
		},
		{
			name: "rocky 9 from os-release",
			in:   KernelEvidence{Release: "5.14.0-427.13.1.el9_4.x86_64", OSImage: "Rocky Linux 9.4 (Blue Onyx)", OSID: "rocky", OSVersionID: "9.4"},
			want: KernelPackage{Distro: DistroRocky, DistroVersion: "9", Type: PackageTypeRPM, Name: "kernel", Version: "5.14.0-427.13.1.el9_4"},
		},
		{
			name: "alma 8",
			in:   KernelEvidence{Release: "4.18.0-513.5.1.el8_9.x86_64", OSImage: "AlmaLinux 8.9 (Midnight Oncilla)"},
			want: KernelPackage{Distro: DistroAlma, DistroVersion: "8", Type: PackageTypeRPM, Name: "kernel", Version: "4.18.0-513.5.1.el8_9"},
		},
		{
			name: "ubuntu 22.04 ga generic",
			in: KernelEvidence{
				Release:     "5.15.0-105-generic",
				ProcVersion: "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-007) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024",
				OSID:        "ubuntu", OSVersionID: "22.04",
			},
			want: KernelPackage{Distro: DistroUbuntu, DistroVersion: "22.04", Type: PackageTypeDeb, Name: "linux", Version: "5.15.0-105.115"},
		},
		{
			name: "ubuntu 20.04 hwe generic",
			in: KernelEvidence{
				Release:     "5.15.0-105-generic",
				ProcVersion: "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-054) #115~20.04.1-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024",
				OSID:        "ubuntu", OSVersionID: "20.04",
			},
			want: KernelPackage{Distro: DistroUbuntu, DistroVersion: "20.04", Type: PackageTypeDeb, Name: "linux-hwe-5.15", Version: "5.15.0-105.115~20.04.1"},
		},
		{
			name: "ubuntu 20.04 aws backport",
			in: KernelEvidence{
				Release:     "5.15.0-1057-aws",
				ProcVersion: "Linux version 5.15.0-1057-aws (buildd@lcy02-amd64-033) #63~20.04.1-Ubuntu SMP Mon Mar 25 10:29:11 UTC 2024",
				OSImage:     "Ubuntu 20.04.6 LTS", OSID: "ubuntu", OSVersionID: "20.04",
			},
			want: KernelPackage{Distro: DistroUbuntu, DistroVersion: "20.04", Type: PackageTypeDeb, Name: "linux-aws-5.15", Version: "5.15.0-1057.63~20.04.1"},
		},
		{
			name: "ubuntu 24.04 oracle backport",
			in: KernelEvidence{
				Release:     "6.14.0-1012-oracle",
				ProcVersion: "Linux version 6.14.0-1012-oracle (buildd@x) #12~24.04.1-Ubuntu SMP",
				OSID:        "ubuntu", OSVersionID: "24.04",
			},
			want: KernelPackage{Distro: DistroUbuntu, DistroVersion: "24.04", Type: PackageTypeDeb, Name: "linux-oracle-6.14", Version: "6.14.0-1012.12~24.04.1"},
		},
		{
			name: "debian 12",
			in: KernelEvidence{
				Release:     "6.1.0-18-amd64",
				ProcVersion: "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)",
				OSImage:     "Debian GNU/Linux 12 (bookworm)", OSID: "debian", OSVersionID: "12",
			},
			want: KernelPackage{Distro: DistroDebian, DistroVersion: "12", Type: PackageTypeDeb, Name: "linux", Version: "6.1.76-1"},
		},
		{
			name: "debian 12 security update",
			in: KernelEvidence{
				Release:     "6.1.0-28-cloud-amd64",
				ProcVersion: "Linux version 6.1.0-28-cloud-amd64 (debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)",
				OSID:        "debian", OSVersionID: "12",
			},
			want: KernelPackage{Distro: DistroDebian, DistroVersion: "12", Type: PackageTypeDeb, Name: "linux", Version: "6.1.119-1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReconstructKernel(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReconstructKernelGaps(t *testing.T) {
	ubuntuProc := "Linux version 5.15.0-1057-aws (buildd@lcy02-amd64-033) #63-Ubuntu SMP Mon Mar 25 10:27:19 UTC 2024"
	tests := []struct {
		name   string
		in     KernelEvidence
		reason string
	}{
		{name: "no release", in: KernelEvidence{OSImage: "Amazon Linux 2"}, reason: "kernel version not reported"},
		{name: "bottlerocket", in: KernelEvidence{Release: "6.1.72", OSImage: "Bottlerocket OS 1.19.0 (aws-k8s-1.29)"}, reason: `unsupported kernel "6.1.72" on "Bottlerocket OS 1.19.0 (aws-k8s-1.29)"`},
		{name: "cos", in: KernelEvidence{Release: "6.1.75+", OSImage: "Container-Optimized OS from Google"}, reason: `unsupported kernel "6.1.75+" on "Container-Optimized OS from Google"`},
		{name: "no os image", in: KernelEvidence{Release: "6.1.75"}, reason: `unsupported kernel "6.1.75": operating system not reported`},
		{name: "rhcos", in: KernelEvidence{Release: "5.14.0-284.54.1.el9_2.x86_64", OSImage: "Red Hat Enterprise Linux CoreOS 414.92.202402201520-0 (Plow)"}, reason: `unsupported kernel "5.14.0-284.54.1.el9_2.x86_64" on "Red Hat Enterprise Linux CoreOS 414.92.202402201520-0 (Plow)"`},
		{name: "os-release id wins over image", in: KernelEvidence{Release: "5.14.0-362.8.1.el9_3.x86_64", OSImage: "Red Hat Enterprise Linux 9.3 (Plow)", OSID: "centos"}, reason: `unsupported kernel "5.14.0-362.8.1.el9_3.x86_64" on "Red Hat Enterprise Linux 9.3 (Plow)"`},
		{name: "rhel realtime kernel", in: KernelEvidence{Release: "5.14.0-362.8.1.el9_3.x86_64+rt", OSImage: "Red Hat Enterprise Linux 9.3 (Plow)"}, reason: `unrecognized Enterprise Linux kernel release "5.14.0-362.8.1.el9_3.x86_64+rt"`},
		{name: "amazon release without tag", in: KernelEvidence{Release: "6.1.79-99.164.x86_64", OSImage: "Amazon Linux 2023"}, reason: `unrecognized Amazon Linux kernel release "6.1.79-99.164.x86_64"`},
		{name: "amazon unknown series", in: KernelEvidence{Release: "6.6.10-1.amzn2023.x86_64", OSImage: "Amazon Linux 2023"}, reason: "unsupported Amazon Linux 2023 kernel series 6.6"},
		{name: "ubuntu on cli", in: KernelEvidence{Release: "5.15.0-1057-aws", OSImage: "Ubuntu 22.04.4 LTS"}, reason: "KernelVersion host data not found"},
		{name: "ubuntu without os-release", in: KernelEvidence{Release: "5.15.0-1057-aws", OSImage: "Ubuntu 22.04.4 LTS", ProcVersion: ubuntuProc}, reason: "OsReleaseFile host data not found"},
		{name: "ubuntu unknown flavour", in: KernelEvidence{Release: "5.15.0-1057-nvidia", ProcVersion: ubuntuProc, OSID: "ubuntu", OSVersionID: "22.04"}, reason: `unsupported Ubuntu kernel flavour "nvidia"`},
		{name: "ubuntu unknown release", in: KernelEvidence{Release: "5.15.0-1057-aws", ProcVersion: ubuntuProc, OSID: "ubuntu", OSVersionID: "18.04"}, reason: `unsupported Ubuntu release "18.04"`},
		{name: "ubuntu proc version for another kernel", in: KernelEvidence{Release: "5.15.0-1058-aws", ProcVersion: ubuntuProc, OSID: "ubuntu", OSVersionID: "22.04"}, reason: `kernel build tag for "5.15.0-1058-aws" not found in /proc/version`},
		{name: "ubuntu backport tag on ga series", in: KernelEvidence{Release: "5.15.0-1057-aws", ProcVersion: "Linux version 5.15.0-1057-aws (buildd@x) #63~20.04.1-Ubuntu SMP", OSID: "ubuntu", OSVersionID: "22.04"}, reason: `kernel "5.15.0-1057-aws" does not match a known Ubuntu 22.04 source package`},
		{name: "ubuntu non-ga series without backport tag", in: KernelEvidence{Release: "6.8.0-1015-aws", ProcVersion: "Linux version 6.8.0-1015-aws (buildd@x) #16-Ubuntu SMP", OSID: "ubuntu", OSVersionID: "22.04"}, reason: `kernel "6.8.0-1015-aws" does not match a known Ubuntu 22.04 source package`},
		{name: "ubuntu backport the flavour does not publish", in: KernelEvidence{Release: "6.2.0-1018-oracle", ProcVersion: "Linux version 6.2.0-1018-oracle (buildd@x) #20~22.04.1-Ubuntu SMP", OSID: "ubuntu", OSVersionID: "22.04"}, reason: `kernel "6.2.0-1018-oracle" does not match a known Ubuntu 22.04 source package`},
		{name: "ubuntu unknown backport series", in: KernelEvidence{Release: "6.17.0-1002-aws", ProcVersion: "Linux version 6.17.0-1002-aws (buildd@x) #2~24.04.1-Ubuntu SMP", OSID: "ubuntu", OSVersionID: "24.04"}, reason: `kernel "6.17.0-1002-aws" does not match a known Ubuntu 24.04 source package`},
		{name: "debian on cli", in: KernelEvidence{Release: "6.1.0-18-amd64", OSImage: "Debian GNU/Linux 12 (bookworm)"}, reason: "KernelVersion host data not found"},
		{name: "debian backports kernel", in: KernelEvidence{Release: "6.12.9+bpo-amd64", ProcVersion: "Linux version 6.12.9+bpo-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.9-1~bpo12+1 (2025-01-19)", OSID: "debian", OSVersionID: "12"}, reason: `Debian kernel package version for "6.12.9+bpo-amd64" not found in /proc/version`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReconstructKernel(tt.in)
			require.Error(t, err)
			assert.Equal(t, tt.reason, err.Error())
		})
	}
}
