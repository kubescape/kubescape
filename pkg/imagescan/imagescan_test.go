package imagescan

import (
	"context"
	"strings"
	"testing"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/presenter"
	"github.com/stretchr/testify/assert"
)

func TestNewVulnerabilityDBMatchesGrype(t *testing.T) {
	dbCfg, shouldUpdate := NewDefaultDBConfig()

	wantStore, wantStatus, wantCloser, wantErr := grype.LoadVulnerabilityDB(dbCfg, shouldUpdate)
	gotStore, gotStatus, gotCloser, gotErr := NewVulnerabilityDB(dbCfg, shouldUpdate)

	assert.Equal(t, wantStore, gotStore)
	assert.Equal(t, wantStatus, gotStatus)
	assert.Equal(t, wantCloser, gotCloser)
	assert.Equal(t, wantErr, gotErr)
}

func TestNewScanService(t *testing.T) {
	dbCfg, _ := NewDefaultDBConfig()

	svc := NewScanService(dbCfg)

	assert.IsType(t, Service{}, svc)
}

func TestScan(t *testing.T) {
	tt := []struct {
		name  string
		image string
	}{
		{
			name:  "performs as scan",
			image: "nginx",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dbCfg, _ := NewDefaultDBConfig()

			svc := NewScanService(dbCfg)

			scanResults, err := svc.Scan(ctx, tc.image)

			presenterConfig, _ := presenter.ValidatedConfig("json", "", false)
			pres := presenter.GetPresenter(presenterConfig, *scanResults)

			var out strings.Builder
			pres.Present(&out)

			t.Logf("Res: %v, err: %v", out.String(), err)
			assert.NotNil(t, scanResults)
		})
	}
}
