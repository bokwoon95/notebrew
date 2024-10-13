//go:build darwin || freebsd || netbsd

package notebrew

import (
	"io/fs"
	"syscall"
	"time"
)

// CreationTime returns the creation time of a file given its absolute file
// path and fs.FileInfo.
func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec).UTC()
}
