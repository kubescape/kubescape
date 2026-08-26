package shared

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Environment variables that supply registry credentials when the corresponding
// flags are omitted, so a password never has to appear on the command line -
// where it is visible in `ps`, /proc/<pid>/cmdline and shell history.
// gosec's G101 matches on the identifier name alone, so a constant naming the
// password/token variable trips it even though the value is an environment variable
// name and not a credential.
const (
	RegistryUsernameEnvVar = "KUBESCAPE_REGISTRY_USERNAME"
	RegistryPasswordEnvVar = "KUBESCAPE_REGISTRY_PASSWORD" //nolint:gosec // G101 false positive: env var name, not a credential
	RegistryTokenEnvVar    = "KUBESCAPE_REGISTRY_TOKEN"    //nolint:gosec // G101 false positive: env var name, not a credential
)

// RegistryCredentialFlagChanged reports whether any of the named registry credential
// flags was explicitly set on the command line. Callers use it to tell "flag omitted"
// (fall back to the environment) apart from "flag set to an empty value" (an explicit
// request for no credential, which must not be overridden by the environment).
func RegistryCredentialFlagChanged(cmd *cobra.Command, names ...string) bool {
	if cmd == nil {
		return false
	}
	for _, name := range names {
		for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags()} {
			if flag := flags.Lookup(name); flag != nil && flag.Changed {
				return true
			}
		}
	}
	return false
}
