package printer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/require"
)

func TestGitLabSASTPrinter_RejectsMixedScanBeforeWriting(t *testing.T) {
	session := gitLabSessionFixture(t, "C-0057", 9)
	images := []cautils.ImageScanData{{
		Image: "nginx:1.25",
		Matches: match.NewMatches(match.Match{
			Package: grypepkg.Package{ID: "openssl", Name: "openssl", Version: "3.0.0"},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{ID: "CVE-2026-0001", Severity: "High"},
			},
		}),
	}}
	output := filepath.Join(t.TempDir(), "report.json")
	gp := NewGitLabSASTPrinter(false)
	require.NoError(t, gp.SetWriter(context.Background(), output))
	t.Cleanup(func() { _ = gp.CloseWriter() })

	err := gp.ActionPrint(context.Background(), session, images)
	require.ErrorContains(t, err, "separate")
	require.ErrorContains(t, err, "image")
	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Empty(t, raw, "a partial report must not appear to cover both scan types")
}
