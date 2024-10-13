//go:build windows

package notebrew

import (
	"io/fs"
	"syscall"
	"time"
)

// CreationTime returns the creation time of a file given its absolute file
// path and fs.FileInfo.
func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	fileAttributeData, ok := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return time.Time{}
	}
	return time.Unix(0, fileAttributeData.CreationTime.Nanoseconds()).UTC()
}
