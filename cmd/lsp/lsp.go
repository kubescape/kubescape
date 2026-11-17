// Package lsp is the `kubescape lsp` command: a language server that publishes
// the findings of a local scan as editor diagnostics.
package lsp

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	lspserver "github.com/kubescape/kubescape/v4/core/pkg/lsp"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
)

// localScannerFactory is the part of the scan engine the server uses.
type localScannerFactory interface {
	NewLocalScanner(base *cautils.ScanInfo, ids []cautils.PolicyIdentifier) (*core.LocalScanner, error)
}

// GetLSPCmd returns the `kubescape lsp` command. The server speaks LSP over
// standard input and output, and never reaches a cluster.
func GetLSPCmd(ks any) *cobra.Command {
	return &cobra.Command{
		Use:   "lsp",
		Short: "Start the Kubescape language server (LSP over stdio)",
		Long: `Start a Language Server Protocol server on standard input and output.

When a manifest the editor has open is saved, the server scans the workspace as
it is on disk and publishes the findings as diagnostics. Text that has not been
saved is not scanned. No cluster is contacted.

Standard output carries only the protocol; logs go to standard error.`,
		Annotations:   map[string]string{stdoutAnnotation: "true"},
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			factory, ok := ks.(localScannerFactory)
			if !ok {
				return errors.New("the language server is not supported by this build")
			}
			scanInfo := &cautils.ScanInfo{}
			scanInfo.SetScanType(cautils.ScanTypeRepo)
			ids := cautils.BuildPolicyIdentifiers([]string{"workloadscan", "allcontrols"}, v1.KindFramework)
			scanner, err := factory.NewLocalScanner(scanInfo, ids)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			logger.L().Info("Starting the Kubescape language server on standard input and output")
			code, err := lspserver.Serve(ctx, cmd.InOrStdin(), protocolOut, scanner, lspserver.Options{})
			if err != nil {
				logger.L().Warning("the language server ended with an error: " + err.Error())
			}
			if code != 0 {
				return &shared.ExitError{Code: code, Err: fmt.Errorf("the language server ended without a shutdown request (exit code %d)", code)}
			}
			return nil
		},
	}
}

// protocolOut is the process's real standard output, kept for the protocol.
var protocolOut = os.Stdout

// stdoutAnnotation marks the command whose standard output is a protocol channel.
const stdoutAnnotation = "kubescape.io/stdout-is-protocol"

// ClaimStdout keeps everything but the protocol off standard output, when cmd is
// the language server. The root command calls it before it does anything that
// can write: initialising the logger and the rest of its setup.
//
// Standard output is the protocol's channel, so a stray line on it corrupts the
// session: a log written there by the structured logger (--logger-name slog, or
// KS_LOGGER_NAME), a print from a library, a warning. It points os.Stdout at
// standard error, so that anything that writes to it lands there, and keeps the
// real standard output for the protocol, which is given that and nothing else.
// A logger keeps the stream it was made with, which is why this is done before
// the logger is made.
func ClaimStdout(cmd *cobra.Command) {
	if cmd == nil || cmd.Annotations[stdoutAnnotation] != "true" {
		return
	}
	protocolOut = os.Stdout
	os.Stdout = os.Stderr
}
