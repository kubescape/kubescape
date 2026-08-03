package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
)

type imageScanResponse struct {
	Image           string                 `json:"image"`
	Matches         []models.Match         `json:"matches"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	Severities      map[string]int         `json:"severities"`
}

func (ksServer *KubescapeMcpserver) runImageScan(ctx context.Context, imageName, username, regSecret string) ([]byte, error) {
	logger.L().Info(fmt.Sprintf("Starting on-demand MCP container image scan for %s", imageName))

	distCfg, installCfg, _, err := imagescan.NewDefaultDBConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize default Grype database configuration: %w", err)
	}

	svc, err := imagescan.NewScanService(distCfg, installCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize image scan service: %w", err)
	}
	defer svc.Close()

	creds := imagescan.RegistryCredentials{
		Username: username,
		Password: regSecret,
	}

	scanResults, err := svc.Scan(ctx, imageName, creds, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to scan container image %s: %w", imageName, err)
	}

	doc, err := models.NewDocument(
		clio.Identification{},
		scanResults.Packages,
		scanResults.Context,
		scanResults.Matches,
		scanResults.IgnoredMatches,
		scanResults.VulnerabilityProvider,
		nil,
		nil,
		models.DefaultSortStrategy,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vulnerability document: %w", err)
	}

	vulnerabilities := make([]models.Vulnerability, 0)
	seenVulns := make(map[string]bool)
	severities := make(map[string]int)

	for _, m := range doc.Matches {
		if !seenVulns[m.Vulnerability.ID] {
			seenVulns[m.Vulnerability.ID] = true
			vulnerabilities = append(vulnerabilities, m.Vulnerability)
		}
		severities[m.Vulnerability.Severity]++
	}

	response := imageScanResponse{
		Image:           imageName,
		Matches:         doc.Matches,
		Vulnerabilities: vulnerabilities,
		Severities:      severities,
	}

	return json.Marshal(response)
}
