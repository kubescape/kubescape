package printer

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func csvReadRecords(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	records, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)
	return records
}

func csvRunImageActionPrint(t *testing.T, imageScanData []cautils.ImageScanData) [][]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "images.csv")
	f, err := os.Create(path)
	require.NoError(t, err)

	cp := NewCsvPrinter(false)
	cp.writer = f
	require.NoError(t, cp.ActionPrint(context.Background(), nil, imageScanData))
	require.NoError(t, cp.CloseWriter())
	return csvReadRecords(t, path)
}

func TestActionPrint_Csv_ImageScan(t *testing.T) {
	records := csvRunImageActionPrint(t, mdImageScanDataFixture())

	require.Len(t, records, 4)
	assert.Equal(t, csvImageHeader, records[0])
	assert.Equal(t, []string{
		"registry.example.com/app:v1", "linux/amd64", "Medium", "CVE-2026-0002", "busybox", "1.36.0",
		"not-fixed", "", "true", "0.63894", "0.99215", "", "",
	}, records[1], "a KEV finding is listed first within its image")
	assert.Equal(t, []string{
		"registry.example.com/app:v1", "linux/amd64", "Critical", "CVE-2026-0001", "openssl", "1.0.0",
		"fixed", "1.0.1; 1.0.2", "false", "0.0004", "0.12", "", "",
	}, records[2])
	assert.Equal(t, []string{
		"registry.example.com/app:v1", "linux/arm64", "High", "CVE-2026-0003", "glibc", "2.39",
		"wont-fix", "", "false", "", "", "", "",
	}, records[3])
}

func TestActionPrint_Csv_ImageScanUnknownMetadataAndVex(t *testing.T) {
	noMetadata := mdImageMatch("GHSA-xxxx-yyyy-zzzz", "", "left-pad", "1.0.0", vulnerability.FixStateUnknown)
	noMetadata.Vulnerability.Metadata = nil

	records := csvRunImageActionPrint(t, []cautils.ImageScanData{
		{
			Image:   "registry.example.com/app:v2",
			Matches: match.NewMatches(noMetadata, mdImageMatch("CVE-2026-0004", "Low", "zlib", "1.3", vulnerability.FixStateNotFixed)),
			VexStatuses: map[string]cautils.VexStatus{
				"CVE-2026-0004": {Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"},
			},
		},
	})

	require.Len(t, records, 3)
	byID := map[string][]string{records[1][3]: records[1], records[2][3]: records[2]}

	unknown := byID["GHSA-xxxx-yyyy-zzzz"]
	require.NotNil(t, unknown)
	assert.Equal(t, "Unknown", unknown[2])
	assert.Empty(t, unknown[1], "an image scanned without a platform leaves the column empty")
	assert.Empty(t, unknown[8], "KEV is blank when the match carries no metadata")

	vex := byID["CVE-2026-0004"]
	require.NotNil(t, vex)
	assert.Equal(t, "not_affected", vex[11])
	assert.Equal(t, "vulnerable_code_not_in_execute_path", vex[12])
}

func TestActionPrint_Csv_ImageScanNoVulnerabilitiesWritesHeader(t *testing.T) {
	records := csvRunImageActionPrint(t, []cautils.ImageScanData{
		{Image: "registry.example.com/clean:v1", Matches: match.NewMatches()},
	})

	require.Len(t, records, 1)
	assert.Equal(t, csvImageHeader, records[0])
}

func TestActionPrint_Csv_ImageScanNeutralizesFormulaInjection(t *testing.T) {
	records := csvRunImageActionPrint(t, []cautils.ImageScanData{
		{
			Image:   "=evil/image:v1",
			Matches: match.NewMatches(mdImageMatch("CVE-2026-0005", "High", "@pkg", "+1", vulnerability.FixStateFixed, "-2")),
		},
	})

	require.Len(t, records, 2)
	assert.Equal(t, "'=evil/image:v1", records[1][0])
	assert.Equal(t, "'@pkg", records[1][4])
	assert.Equal(t, "'+1", records[1][5])
	assert.Equal(t, "'-2", records[1][7])
}

func TestActionPrint_Csv_ScanImagesWritesCompanionFile(t *testing.T) {
	dir := t.TempDir()
	posturePath := filepath.Join(dir, "results.csv")
	f, err := os.Create(posturePath)
	require.NoError(t, err)

	cp := NewCsvPrinter(false)
	cp.writer = f
	require.NoError(t, cp.ActionPrint(context.Background(), csvSessionFixture(), mdImageScanDataFixture()))
	require.NoError(t, cp.CloseWriter())

	posture := csvReadRecords(t, posturePath)
	require.NotEmpty(t, posture)
	assert.Equal(t, "Control Name", posture[0][0])

	images := csvReadRecords(t, filepath.Join(dir, "results-vulnerabilities.csv"))
	require.Len(t, images, 4)
	assert.Equal(t, csvImageHeader, images[0])
}

func TestActionPrint_Csv_PostureScanWithoutImagesWritesNoCompanionFile(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "results.csv"))
	require.NoError(t, err)

	cp := NewCsvPrinter(false)
	cp.writer = f
	require.NoError(t, cp.ActionPrint(context.Background(), csvSessionFixture(), nil))
	require.NoError(t, cp.CloseWriter())

	_, err = os.Stat(filepath.Join(dir, "results-vulnerabilities.csv"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestActionPrint_Csv_ScanImagesToNonRegularOutputSkipsCompanionFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	drained := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(r)
		drained <- out
	}()

	cp := NewCsvPrinter(false)
	cp.writer = w
	require.NoError(t, cp.ActionPrint(context.Background(), csvSessionFixture(), mdImageScanDataFixture()))
	require.NoError(t, w.Close())

	records, err := csv.NewReader(bytes.NewReader(<-drained)).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Equal(t, "Control Name", records[0][0])

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestActionPrint_Csv_ScanImagesToDevNullSkipsCompanionFile(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)

	cp := NewCsvPrinter(false)
	cp.writer = f
	require.NoError(t, cp.ActionPrint(context.Background(), csvSessionFixture(), mdImageScanDataFixture()))
	require.NoError(t, cp.CloseWriter())
}

func TestActionPrint_Csv_ScanImagesRefusesCompanionAliasingPostureReport(t *testing.T) {
	for _, tc := range []struct {
		name string
		link func(oldname, newname string) error
	}{
		{name: "hard link", link: os.Link},
		{name: "symlink", link: os.Symlink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			posturePath := filepath.Join(dir, "results.csv")
			f, err := os.Create(posturePath)
			require.NoError(t, err)
			if err := tc.link(posturePath, filepath.Join(dir, "results-vulnerabilities.csv")); err != nil {
				_ = f.Close()
				t.Skipf("cannot create %s: %v", tc.name, err)
			}

			cp := NewCsvPrinter(false)
			cp.writer = f
			err = cp.ActionPrint(context.Background(), csvSessionFixture(), mdImageScanDataFixture())
			require.NoError(t, cp.CloseWriter())
			require.ErrorContains(t, err, "is the same file as the posture report")

			posture := csvReadRecords(t, posturePath)
			require.NotEmpty(t, posture)
			assert.Equal(t, "Control Name", posture[0][0])
		})
	}
}
