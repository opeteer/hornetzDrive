//go:build !windows

package storage

import (
	"syscall"
)

// GetTotalDiskCapacity returns the total filesystem capacity in bytes for the specified path.
func GetTotalDiskCapacity(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Blocks) * int64(stat.Bsize), nil
}
