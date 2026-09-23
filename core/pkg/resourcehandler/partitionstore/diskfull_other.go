//go:build !windows

package partitionstore

func isPlatformDiskFull(error) bool {
	return false
}
