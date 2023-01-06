//go:build !gitenabled

package version

func isGitEnabled() bool {
	return false
}
