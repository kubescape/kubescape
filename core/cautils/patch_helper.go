package cautils

import (
	"encoding/json"
	"os"

	kubescapeTypes "github.com/anchore/grype/grype/presenter/models"
	"github.com/project-copacetic/copacetic/pkg/types"
)

type KubescapeParser struct{}

func parseKubescapeReport(file string) (*kubescapeTypes.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var ksr kubescapeTypes.Document
	if err = json.Unmarshal(data, &ksr); err != nil {
		return nil, err
	}

	return &ksr, nil
}

func (k *KubescapeParser) Parse(file string) (*types.UpdateManifest, error) {
	// Parse the kubescape scan results
	report, err := parseKubescapeReport(file)
	if err != nil {
		return nil, err
	}

	updates := types.UpdateManifest{
		OSType:    report.Distro.Name,
		OSVersion: report.Distro.Version,
		Arch:      report.Source.Target.(map[string]interface{})["architecture"].(string),
	}

	// Check if vulnerability is OS-lvl package & check if vulnerability is fixable
	for i := range report.Matches {
		vuln := &report.Matches[i]
		if vuln.Artifact.Language == "" && vuln.Vulnerability.Fix.State == "fixed" {
			updates.Updates = append(updates.Updates, types.UpdatePackage{Name: vuln.Artifact.Name, FixedVersion: vuln.Vulnerability.Fix.Versions[0]})
		}
	}
	return &updates, nil
}
