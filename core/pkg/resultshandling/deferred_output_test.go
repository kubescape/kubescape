package resultshandling

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every printer that can write to a file must keep the old content while the
// scan runs, and replace it completely once the printer is asked to print. A
// printer that forgets printer.PrepareOutput would leave trailing bytes of the
// old report, so this runs over all of them.
func TestPrinters_KeepOldFileUntilActionPrintThenReplaceIt(t *testing.T) {
	formats := printer.AllFormats
	const old = "OLD-REPORT-CONTENT-OLD-REPORT-CONTENT-OLD-REPORT-CONTENT"

	for _, format := range formats {
		for _, version := range []string{"", "v1"} {
			if version == "v1" && format != printer.JsonFormat {
				continue
			}
			t.Run(format+version, func(t *testing.T) {
				ctx := context.Background()
				path := filepath.Join(t.TempDir(), "out"+printer.FormatOutputExt[format])
				require.NoError(t, os.WriteFile(path, []byte(old), 0o600))

				p := NewPrinter(ctx, format, &cautils.ScanInfo{FormatVersion: version}, "cluster")
				require.NoError(t, p.SetWriter(ctx, path))

				got, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, old, string(got), "SetWriter must not touch the old report")

				// A scan that fails before printing closes the printers as is.
				failed := NewPrinter(ctx, format, &cautils.ScanInfo{FormatVersion: version}, "cluster")
				require.NoError(t, failed.SetWriter(ctx, path))
				require.NoError(t, ClosePrinter(failed))
				got, err = os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, old, string(got), "closing an unused printer must keep the old report")

				// ActionPrint with no data fails in most printers, but only after
				// it has cleared the old report, so no old bytes can survive a
				// shorter new one.
				_ = p.ActionPrint(ctx, nil, nil)
				got, err = os.ReadFile(path)
				require.NoError(t, err)
				assert.NotContains(t, string(got), old, "ActionPrint must replace the old report")
				_ = ClosePrinter(p)
			})
		}
	}
}
