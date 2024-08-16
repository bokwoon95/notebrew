//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package notebrew

import (
	"io/fs"
	"time"
)

// CreationTime returns the creation time of a file given its absolute file
// path and fs.FileInfo.
func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	return time.Time{}
}
