package notebrew

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

// DirectoryFSConfig holds the parameters needed to construct a DirectoryFS.
type DirectoryFSConfig struct {
	// Root directory of the DirectoryFS.
	RootDir string

	// Temp directory of the DirectoryFS.
	TempDir string
}

// DirectoryFS implements a writeable filesystem using a local directory.
//
// NOTE: Each FS method should only ever work with forward slash file path
// separators. Even on Windows, because Windows accepts forward slash file path
// separators just fine. This simplifies our implementation a lot because we
// only ever have to think about forward slashes.
type DirectoryFS struct {
	// RootDir is the root directory of the DirectoryFS. Has to be an absolute
	// path!!
	RootDir string

	// TempDir is used to store files while they are being written before being
	// renamed to their target destination when complete.
	//
	// Windows is the exception, as os.Rename on the temporary files (even
	// after I've closed them) intermittently returns "Access is denied" for no
	// discernable reason so I've skipped the temp file into rename workflow
	// for Windows entirely.
	TempDir string

	// ctx provides the context of all operations called on the DirectoryFS.
	ctx context.Context
}

// NewDirectoryFS constructs a new DirectoryFS.
func NewDirectoryFS(config DirectoryFSConfig) (*DirectoryFS, error) {
	rootDir, err := filepath.Abs(config.RootDir)
	if err != nil {
		return nil, err
	}
	tempDir, err := filepath.Abs(config.TempDir)
	if err != nil {
		return nil, err
	}
	directoryFS := &DirectoryFS{
		ctx:     context.Background(),
		RootDir: filepath.ToSlash(rootDir),
		TempDir: filepath.ToSlash(tempDir),
	}
	return directoryFS, nil
}

// As writes the current directoryFS into the target if it is a valid
// DirectoryFS pointer.
func (fsys *DirectoryFS) As(target any) bool {
	switch target := target.(type) {
	case *DirectoryFS:
		*target = *fsys
		return true
	case **DirectoryFS:
		*target = fsys
		return true
	default:
		return false
	}
}

// WithContext returns a new FS with the given context.
func (fsys *DirectoryFS) WithContext(ctx context.Context) FS {
	return &DirectoryFS{
		RootDir: fsys.RootDir,
		TempDir: fsys.TempDir,
		ctx:     ctx,
	}
}

// Open implements the Open FS operation for DirectoryFS.
func (fsys *DirectoryFS) Open(name string) (fs.File, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	file, err := os.Open(path.Join(fsys.RootDir, name))
	if err != nil {
		return nil, err
	}
	return file, nil
}

// Stat implements the fs.StatFS interface.
func (fsys *DirectoryFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	fileInfo, err := os.Stat(path.Join(fsys.RootDir, name))
	if err != nil {
		return nil, stacktrace.New(err)
	}
	return fileInfo, nil
}

// OpenWriter implements the OpenWriter FS operation for DirectoryFS.
func (fsys *DirectoryFS) OpenWriter(name string, _ fs.FileMode) (io.WriteCloser, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if runtime.GOOS == "windows" {
		file, err := os.OpenFile(path.Join(fsys.RootDir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return nil, stacktrace.New(err)
		}
		return file, nil
	}
	_, err = os.Stat(path.Join(fsys.RootDir, path.Dir(name)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
		return nil, stacktrace.New(err)
	}
	file := &DirectoryFileWriter{
		ctx:     fsys.ctx,
		rootDir: fsys.RootDir,
		tempDir: fsys.TempDir,
		name:    name,
	}
	if file.tempDir == "" {
		file.tempDir = os.TempDir()
	}
	file.tempFile, err = os.CreateTemp(file.tempDir, "notebrew-temp-*"+path.Ext(name))
	if err != nil {
		return nil, stacktrace.New(err)
	}
	fileInfo, err := file.tempFile.Stat()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	file.tempName = fileInfo.Name()
	return file, nil
}

// DirectoryFileWriter represents a writable file on a DirectoryFS.
type DirectoryFileWriter struct {
	// ctx provides the context of all operations called on the file.
	ctx context.Context

	// rootDir is the root directory that houses the destination file.
	rootDir string

	// name is the name of the destination file relative to rootDir.
	name string

	// tempFile is temporary file we are writing to first before we do an
	// atomic rename into the destination file. This ensures that parallel
	// writers do not corrupt the destination file, writes are always all or
	// nothing and the last writer wins.
	tempFile *os.File

	// tempDir is the temp directory that houses the temporary file.
	tempDir string

	// tempName is the name of the temporary file relative to tempDir. It is
	// randomly generated by os.CreateTemp.
	tempName string

	// writeFailed records if any writes to the tempFile failed.
	writeFailed bool
}

// ReadFrom implements io.ReaderFrom.
func (file *DirectoryFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, stacktrace.New(err)
	}
	n, err = file.tempFile.ReadFrom(r)
	if err != nil {
		file.writeFailed = true
		return n, stacktrace.New(err)
	}
	return n, nil
}

// Write writes len(b) bytes from b to the DirectoryFileWriter. It returns the
// number of bytes written and an error, if any. Write returns a non-nil error
// when n != len(b).
func (file *DirectoryFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, stacktrace.New(err)
	}
	n, err = file.tempFile.Write(p)
	if err != nil {
		file.writeFailed = true
		return n, stacktrace.New(err)
	}
	return n, nil
}

// Close saves the contents of the DirectoryFileWriter into a file and closes
// the DirectoryFileWriter.
func (file *DirectoryFileWriter) Close() error {
	tempFilePath := path.Join(file.tempDir, file.tempName)
	destFilePath := path.Join(file.rootDir, file.name)
	defer os.Remove(tempFilePath)
	err := file.tempFile.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	if file.writeFailed {
		return nil
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

// ReadDir implements the ReadDir FS operation for DirectoryFS.
func (fsys *DirectoryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	return os.ReadDir(path.Join(fsys.RootDir, name))
}

// Mkdir implements the Mkdir FS operation for DirectoryFS.
func (fsys *DirectoryFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	return os.Mkdir(path.Join(fsys.RootDir, name), 0755)
}

// MkdirAll implements the MkdirAll FS operation for DirectoryFS.
func (fsys *DirectoryFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	return os.MkdirAll(path.Join(fsys.RootDir, name), 0755)
}

// Remove implements the Remove FS operation for DirectoryFS.
func (fsys *DirectoryFS) Remove(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	return os.Remove(path.Join(fsys.RootDir, name))
}

// RemoveAll implements the RemoveAll FS operation for DirectoryFS.
func (fsys *DirectoryFS) RemoveAll(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	return os.RemoveAll(path.Join(fsys.RootDir, name))
}

// Rename implements the Rename FS operation for DirectoryFS.
func (fsys *DirectoryFS) Rename(oldName, newName string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(oldName) || strings.Contains(oldName, "\\") {
		return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newName) || strings.Contains(newName, "\\") {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrInvalid}
	}
	_, err = os.Stat(path.Join(fsys.RootDir, newName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
	} else {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrExist}
	}
	err = os.Rename(path.Join(fsys.RootDir, oldName), path.Join(fsys.RootDir, newName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
		}
		return nil
	}
	return nil
}

// Copy implements the Copy FS operation for DirectoryFS.
func (fsys *DirectoryFS) Copy(srcName, destName string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(srcName) || strings.Contains(srcName, "\\") {
		return &fs.PathError{Op: "copy", Path: srcName, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(destName) || strings.Contains(destName, "\\") {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrInvalid}
	}
	// Make sure destName does not exist.
	_, err = os.Stat(path.Join(fsys.RootDir, destName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
	} else {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrExist}
	}
	// Make sure srcName exists.
	srcFileInfo, err := os.Stat(path.Join(fsys.RootDir, srcName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "copy", Path: srcName, Err: fs.ErrNotExist}
		}
		return stacktrace.New(err)
	}
	// If srcFile is a file, we can just copy the file and be done with it.
	if !srcFileInfo.IsDir() {
		srcFile, err := fsys.WithContext(fsys.ctx).Open(srcName)
		if err != nil {
			return stacktrace.New(err)
		}
		defer srcFile.Close()
		destFile, err := fsys.WithContext(fsys.ctx).OpenWriter(destName, 0644)
		if err != nil {
			return stacktrace.New(err)
		}
		defer destFile.Close()
		_, err = io.Copy(destFile, srcFile)
		if err != nil {
			return stacktrace.New(err)
		}
		err = destFile.Close()
		if err != nil {
			return stacktrace.New(err)
		}
		return nil
	}
	// Otherwise, we'll need to recursively walk the directory and copy each
	// file and directory we find along the way.
	//
	// We're passing in srcName as the root to fs.WalkDir and not
	// path.Join(fsys.RootDir, srcName) because fs.WalkDir calls fsys.ReadDir()
	// under the hood, and fsys.ReadDir() internally already converts srcName
	// to path.Join(fsys.RootDir, srcName).
	group, groupctx := errgroup.WithContext(fsys.ctx)
	err = fs.WalkDir(fsys.WithContext(groupctx), srcName, func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return stacktrace.New(err)
		}
		relativePath := strings.TrimPrefix(strings.TrimPrefix(filePath, srcName), "/")
		if dirEntry.IsDir() {
			err := fsys.WithContext(groupctx).MkdirAll(path.Join(destName, relativePath), 0755)
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		}
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			srcFile, err := fsys.WithContext(groupctx).Open(filePath)
			if err != nil {
				return stacktrace.New(err)
			}
			defer srcFile.Close()
			destFile, err := fsys.WithContext(groupctx).OpenWriter(path.Join(destName, relativePath), 0644)
			if err != nil {
				return stacktrace.New(err)
			}
			defer destFile.Close()
			_, err = io.Copy(destFile, srcFile)
			if err != nil {
				return stacktrace.New(err)
			}
			err = destFile.Close()
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return err
	}
	err = group.Wait()
	if err != nil {
		return err
	}
	return nil
}
