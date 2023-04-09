// Package getter provides functionality to retrieve policy objects.
//
// It comes with 3 implementations:
//
// * KSCloudAPI is a client for the KS Cloud SaaS API
// * LoadPolicy exposes policy objects stored in a local repository
// * DownloadReleasedPolicy downloads policy objects from the policy library released on github: https://github.com/kubescape/regolibrary
package getter
