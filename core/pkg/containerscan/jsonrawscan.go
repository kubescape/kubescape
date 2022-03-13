package containerscan

var nginxScanJSON = `
{
    "customerGUID": "1e3a88bf-92ce-44f8-914e-cbe71830d566",
    "imageTag": "nginx:1.18.0",
    "imageHash": "",
    "wlid": "wlid://cluster-test/namespace-test/deployment-davidg",
    "containerName": "nginx-1",
    "timestamp": 1628091365,
    "layers": [
        {
            "layerHash": "sha256:f7ec5a41d630a33a2d1db59b95d89d93de7ae5a619a3a8571b78457e48266eba",
            "parentLayerHash": "",
            "vulnerabilities": [
                {
                    "name": "CVE-2009-0854",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "dash",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0854",
                    "description": "Untrusted search path vulnerability in dash 0.5.4, when used as a login shell, allows local users to execute arbitrary code via a Trojan horse .profile file in the current working directory.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2019-13627",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "libgcrypt20",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13627",
                    "description": "It was discovered that there was a ECDSA timing attack in the libgcrypt20 cryptographic library. Version affected: 1.8.4-5, 1.7.6-2+deb9u3, and 1.6.3-2+deb8u4. Versions fixed: 1.8.5-2 and 1.6.3-2+deb8u7.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2021-33560",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "libgcrypt20",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33560",
                    "description": "Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. (There is also an interoperability problem because the selection of the k integer value does not properly consider the differences between basic ElGamal encryption and generalized ElGamal encryption.) This, for example, affects use of ElGamal in OpenPGP.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:1.8.4-5+deb10u1"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2021-3345",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "libgcrypt20",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3345",
                    "description": "_gcry_md_block_write in cipher/hash-common.c in Libgcrypt version 1.9.0 has a heap-based buffer overflow when the digest final function sets a large count value. It is recommended to upgrade to 1.9.1 or later.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2010-0834",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "base-files",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0834",
                    "description": "The base-files package before 5.0.0ubuntu7.1 on Ubuntu 9.10 and before 5.0.0ubuntu20.10.04.2 on Ubuntu 10.04 LTS, as shipped on Dell Latitude 2110 netbooks, does not require authentication for package installation, which allows remote archive servers and man-in-the-middle attackers to execute arbitrary code via a crafted package.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2018-6557",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "base-files",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6557",
                    "description": "The MOTD update script in the base-files package in Ubuntu 18.04 LTS before 10.1ubuntu2.2, and Ubuntu 18.10 before 10.1ubuntu6 incorrectly handled temporary files. A local attacker could use this issue to cause a denial of service, or possibly escalate privileges if kernel symlink restrictions were disabled.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2013-0223",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0223",
                    "description": "The SUSE coreutils-i18n.patch for GNU coreutils allows context-dependent attackers to cause a denial of service (segmentation fault and crash) via a long string to the join command, when using the -i switch, which triggers a stack-based buffer overflow in the alloca function.",
                    "severity": "Low",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2015-4041",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4041",
                    "description": "The keycompare_mb function in sort.c in sort in GNU Coreutils through 8.23 on 64-bit platforms performs a size calculation without considering the number of bytes occupied by multibyte characters, which allows attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via long UTF-8 strings.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2009-4135",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-4135",
                    "description": "The distcheck rule in dist-check.mk in GNU coreutils 5.2.1 through 8.1 allows local users to gain privileges via a symlink attack on a file in a directory tree under /tmp.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2015-4042",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4042",
                    "description": "Integer overflow in the keycompare_mb function in sort.c in sort in GNU Coreutils through 8.23 might allow attackers to cause a denial of service (application crash) or possibly have unspecified other impact via long strings.",
                    "severity": "Critical",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2013-0221",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0221",
                    "description": "The SUSE coreutils-i18n.patch for GNU coreutils allows context-dependent attackers to cause a denial of service (segmentation fault and crash) via a long string to the sort command, when using the (1) -d or (2) -M switch, which triggers a stack-based buffer overflow in the alloca function.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2013-0222",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0222",
                    "description": "The SUSE coreutils-i18n.patch for GNU coreutils allows context-dependent attackers to cause a denial of service (segmentation fault and crash) via a long string to the uniq command, which triggers a stack-based buffer overflow in the alloca function.",
                    "severity": "Low",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2016-2781",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2781",
                    "description": "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2017-18018",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "coreutils",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18018",
                    "description": "In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX \"-R -L\" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2021-20193",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "tar",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20193",
                    "description": "A flaw was found in the src/list.c of tar 1.33 and earlier. This flaw allows an attacker who can submit a crafted input file to tar to cause uncontrolled consumption of memory. The highest threat from this vulnerability is to system availability.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2005-2541",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "tar",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2541",
                    "description": "Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2019-9923",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "tar",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9923",
                    "description": "pax_decode_header in sparse.c in GNU Tar before 1.32 had a NULL pointer dereference when parsing certain archives that have malformed extended headers.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2018-1000654",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "libtasn1-6",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000654",
                    "description": "GNU Libtasn1-4.13 libtasn1-4.13 version libtasn1-4.13, libtasn1-4.12 contains a DoS, specifically CPU usage will reach 100% when running asn1Paser against the POC due to an issue in _asn1_expand_object_id(p_tree), after a long time, the program will be killed. This attack appears to be exploitable via parsing a crafted file.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2011-3374",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "apt",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3374",
                    "description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
                    "severity": "Medium",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2021-37600",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "util-linux",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37600",
                    "description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file.",
                    "severity": "Unknown",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2007-0822",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "util-linux",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0822",
                    "description": "umount, when running with the Linux 2.6.15 kernel on Slackware Linux 10.2, allows local users to trigger a NULL dereference and application crash by invoking the program with a pathname for a USB pen drive that was mounted and then physically removed, which might allow the users to obtain sensitive information, including core file contents.",
                    "severity": "Low",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2004-1349",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "gzip",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1349",
                    "description": "gzip before 1.3 in Solaris 8, when called with the -f or -force flags, will change the permissions of files that are hard linked to the target files, which allows local users to view or modify these files.",
                    "severity": "Low",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2004-0603",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "gzip",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0603",
                    "description": "gzexe in gzip 1.3.3 and earlier will execute an argument when the creation of a temp file fails instead of exiting the program, which could allow remote attackers or local users to execute arbitrary commands, a different vulnerability than CVE-1999-1332.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2010-0002",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "bash",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0002",
                    "description": "The /etc/profile.d/60alias.sh script in the Mandriva bash package for Bash 2.05b, 3.0, 3.2, 3.2.48, and 4.0 enables the --show-control-chars option in LS_OPTIONS, which allows local users to send escape sequences to terminal emulators, or hide the existence of a file, via a crafted filename.",
                    "severity": "Low",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                },
                {
                    "name": "CVE-2019-18276",
                    "imageHash": "sha256:c2c45d506085d300b72a6d4b10e3dce104228080a2cf095fc38333afe237e2be",
                    "imageTag": "",
                    "packageName": "bash",
                    "packageVersion": "",
                    "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18276",
                    "description": "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
                    "severity": "High",
                    "metadata": null,
                    "fixedIn": [
                        {
                            "name": "",
                            "imageTag": "",
                            "version": "0:0"
                        }
                    ],
                    "relevant": ""
                }
            ],
            "packageToFile": null
        },
        {
            "layerHash": "sha256:0b20d28b5eb3007f70c43cdd8efcdb04016aa193192e5911cda5b7590ffaa635",
            "parentLayerHash": "sha256:f7ec5a41d630a33a2d1db59b95d89d93de7ae5a619a3a8571b78457e48266eba",
            "vulnerabilities": [],
            "packageToFile": null
        },
        {
            "layerHash": "sha256:1576642c97761adf346890bf67c43473217160a9a203ef47d0bc6020af652798",
            "parentLayerHash": "sha256:0b20d28b5eb3007f70c43cdd8efcdb04016aa193192e5911cda5b7590ffaa635",
            "vulnerabilities": [],
            "packageToFile": null
        },
        {
            "layerHash": "sha256:c12a848bad84d57e3f5faafab5880484434aee3bf8bdde4d519753b7c81254fd",
            "parentLayerHash": "sha256:1576642c97761adf346890bf67c43473217160a9a203ef47d0bc6020af652798",
            "vulnerabilities": [],
            "packageToFile": null
        },
        {
            "layerHash": "sha256:03f221d9cf00a7077231c6dcac3c95182727c7e7fd44fd2b2e882a01dcda2d70",
            "parentLayerHash": "sha256:c12a848bad84d57e3f5faafab5880484434aee3bf8bdde4d519753b7c81254fd",
            "vulnerabilities": [],
            "packageToFile": null
        }
    ],
    "listOfDangerousArtifcats": [
        "bin/dash",
        "bin/bash",
        "usr/bin/curl"
    ]
}
`
