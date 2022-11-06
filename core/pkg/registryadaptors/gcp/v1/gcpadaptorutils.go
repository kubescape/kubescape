package v1

import (
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

func responseObjectToVulnerabilities(vulnerabilityList []*grafeaspb.Occurrence, count int) []registryvulnerabilities.Vulnerability {
	vulnerabilities := make([]registryvulnerabilities.Vulnerability, count)
	for i, vulnerabilityEntry := range vulnerabilityList {
		if vulnerabilityEntry.GetKind().String() != "DISCOVERY" {
			vulnerabilities[i].Name = vulnerabilityEntry.Name
			vulnerabilities[i].NoteName = vulnerabilityEntry.NoteName
			vulnerabilities[i].CreateTime = vulnerabilityEntry.CreateTime.AsTime()
			vulnerabilities[i].UpdateTime = vulnerabilityEntry.UpdateTime.AsTime()
			vulnerabilities[i].CVSS = vulnerabilityEntry.GetVulnerability().CvssScore
			vulnerabilities[i].AffectedCPEURI = vulnerabilityEntry.GetVulnerability().PackageIssue[0].AffectedCpeUri
			vulnerabilities[i].AffectedPackage = vulnerabilityEntry.GetVulnerability().PackageIssue[0].AffectedPackage
			vulnerabilities[i].AffectedVersion = vulnerabilityEntry.GetVulnerability().PackageIssue[0].AffectedVersion.FullName
			vulnerabilities[i].FixedVersion = vulnerabilityEntry.GetVulnerability().PackageIssue[0].FixedVersion.FullName
			vulnerabilities[i].FixedCPEURI = vulnerabilityEntry.GetVulnerability().PackageIssue[0].FixedCpeUri
			vulnerabilities[i].FixedPackege = vulnerabilityEntry.GetVulnerability().PackageIssue[0].FixedPackage
			vulnerabilities[i].FixAvailablePackage = vulnerabilityEntry.GetVulnerability().PackageIssue[0].GetFixAvailable()
			vulnerabilities[i].PackageType = vulnerabilityEntry.GetVulnerability().PackageIssue[0].PackageType
			vulnerabilities[i].EffectiveSeverityPackage = vulnerabilityEntry.GetVulnerability().PackageIssue[0].EffectiveSeverity.String()
			vulnerabilities[i].AffectedPackage = vulnerabilityEntry.GetVulnerability().PackageIssue[0].AffectedPackage
			vulnerabilities[i].Severity = vulnerabilityEntry.GetVulnerability().Severity.Enum().String()
			vulnerabilities[i].ShortDescription = vulnerabilityEntry.GetVulnerability().ShortDescription
			vulnerabilities[i].LongDescription = vulnerabilityEntry.GetVulnerability().LongDescription
		} else {
			vulnerabilities[i].Description = vulnerabilityEntry.GetDiscovery().String()
		}
	}

	return vulnerabilities
}
