package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestFlagUsagesHaveNoBackticks guards against pflag's UnquoteUsage: a
// back-quoted word in a flag's usage replaces the value placeholder ("string")
// shown in --help.
func TestFlagUsagesHaveNoBackticks(t *testing.T) {
	root := NewDefaultKubescapeCommand(context.Background(), "", "", "")
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if strings.Contains(f.Usage, "`") {
				t.Errorf("%s --%s: usage contains a backtick, which --help renders as the value name: %q", c.CommandPath(), f.Name, f.Usage)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}
