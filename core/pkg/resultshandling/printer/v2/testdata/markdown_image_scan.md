# Kubescape Image Scan Report

**Images:** 2

**Vulnerability DB Built:** 2026-08-25T10:30:00Z

## Images

| Image |
|---|
| `registry.example.com/app:v1 [linux/amd64]` |
| `registry.example.com/app:v1 [linux/arm64]` |

## Vulnerability Summary

| Severity | CVEs | Fixable |
|---|---:|---:|
| Critical | 1 | 1 |
| High | 1 | 0 |
| Medium | 1 | 0 |
| **Total** | **3** | **1** |

## Affected Packages

| Package | Version | Score | Critical | High | Medium | Low | Unknown |
|---|---|---:|---:|---:|---:|---:|---:|
| openssl | 1.0.0 | 5 | 1 | 0 | 0 | 0 | 0 |
| glibc | 2.39 | 4 | 0 | 1 | 0 | 0 | 0 |
| busybox | 1.36.0 | 3 | 0 | 0 | 1 | 0 | 0 |

## Vulnerabilities

| Severity | Vulnerability | Package | Version | Fixed In | Image |
|---|---|---|---|---|---|
| Critical | CVE-2026-0001 | openssl | 1.0.0 | 1.0.1, 1.0.2 | `registry.example.com/app:v1 [linux/amd64]` |
| High | CVE-2026-0003 | glibc | 2.39 | wont-fix | `registry.example.com/app:v1 [linux/arm64]` |
| Medium | CVE-2026-0002 | busybox | 1.36.0 |  | `registry.example.com/app:v1 [linux/amd64]` |
