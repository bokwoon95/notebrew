package notebrew

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// SFTPFSConfig holds the parameters needed to construct a SFTPFS.
type SFTPFSConfig struct {
	// (Required) ssh.Client constructor function.
	NewSSHClient func() (*ssh.Client, error)

	// (Required) Root directory on the SFTP server.
	RootDir string

	// Temp directory on the SFTP server.
	TempDir string

	// Max open connections to the SFTP server.
	MaxOpenConns int

	// (Required) Logger is used for reporting errors that cannot be handled
	// and are thrown away.
	Logger *slog.Logger
}

// SFTPFS implements a writeable filesystem using an SFTP server. It maintains
// one or more persistent connections to an SFTP server.
type SFTPFS struct {
	// ssh.Client constructor function.
	NewSSHClient func() (*ssh.Client, error)

	// Root directory on the SFTP server.
	RootDir string

	// Temp directory on the SFTP server.
	TempDir string

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// Clients is the list of available sftp Clients we can use.
	Clients []*SFTPClient

	// index is a atomically incrementing number which used for accessing the
	// list of clients in a round-robin fashion.
	index *atomic.Uint64

	// ctx provides the context of all operations called on the SFTPFS.
	ctx context.Context
}

// NewSFTPFS constructs a new SFTPFS.
func NewSFTPFS(config SFTPFSConfig) (*SFTPFS, error) {
	rootDir := filepath.ToSlash(config.RootDir)
	if rootDir == "" {
		return nil, fmt.Errorf("rootDir cannot be empty")
	} else {
		if !strings.HasPrefix(rootDir, "/") {
			return nil, fmt.Errorf("rootDir is not an absolute path")
		}
	}
	tempDir := filepath.ToSlash(config.TempDir)
	if tempDir != "" {
		if !strings.HasPrefix(tempDir, "/") {
			return nil, fmt.Errorf("tempDir is not an absolute path")
		}
	}
	maxOpenConns := config.MaxOpenConns
	if maxOpenConns < 1 {
		maxOpenConns = 1
	}
	sftpFS := &SFTPFS{
		Clients:      make([]*SFTPClient, 0, maxOpenConns),
		NewSSHClient: config.NewSSHClient,
		RootDir:      rootDir,
		TempDir:      tempDir,
		Logger:       config.Logger,
		index:        &atomic.Uint64{},
		ctx:          context.Background(),
	}
	for i := 0; i < maxOpenConns; i++ {
		sftpFS.Clients = append(sftpFS.Clients, &SFTPClient{})
	}
	_, err := sftpFS.Clients[0].Get(sftpFS.NewSSHClient)
	if err != nil {
		return nil, err
	}
	return sftpFS, nil
}

// As writes the current SFTPFS into the target if it is a valid SFTPFS
// pointer.
func (fsys *SFTPFS) As(target any) bool {
	switch target := target.(type) {
	case *SFTPFS:
		*target = *fsys
		return true
	case **SFTPFS:
		*target = fsys
		return true
	default:
		return false
	}
}

// WithContext returns a new FS with the given context.
func (fsys *SFTPFS) WithContext(ctx context.Context) FS {
	return &SFTPFS{
		Clients:      fsys.Clients,
		NewSSHClient: fsys.NewSSHClient,
		RootDir:      fsys.RootDir,
		TempDir:      fsys.TempDir,
		Logger:       fsys.Logger,
		index:        fsys.index,
		ctx:          ctx,
	}
}

// Open implements the Open FS operation for SFTPFS.
func (fsys *SFTPFS) Open(name string) (fs.File, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	file, err := sftpClient.Open(path.Join(fsys.RootDir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, stacktrace.New(err)
	}
	return file, nil
}

// Stat implements the fs.StatFS interface.
func (fsys *SFTPFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	fileInfo, err := sftpClient.Stat(path.Join(fsys.RootDir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, stacktrace.New(err)
	}
	return fileInfo, nil
}

// OpenWriter implements the OpenWriter FS operation for DatabaseFS.
func (fsys *SFTPFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	_, err = sftpClient.Stat(path.Join(fsys.RootDir, path.Dir(name)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
		return nil, stacktrace.New(err)
	}
	file := &SFTPFileWriter{
		ctx:        fsys.ctx,
		sftpClient: sftpClient,
		rootDir:    fsys.RootDir,
		tempDir:    fsys.TempDir,
		name:       name,
	}
	if file.tempDir == "" {
		file.tempDir = "/tmp"
	}
	file.tempName = NewID().String() + path.Ext(name)
	file.tempFile, err = sftpClient.OpenFile(path.Join(fsys.RootDir, file.tempName), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return nil, stacktrace.New(err)
	}
	return file, nil
}

// SFTPFileWriter represents a writable file on an SFTPFS.
type SFTPFileWriter struct {
	// ctx provides the context of all operations called on the file.
	ctx context.Context

	// SFTP client.
	sftpClient *sftp.Client

	// rootDir is the root directory on the SFTP server.
	rootDir string

	// name is the name of the destination file relative to rootDir.
	name string

	// tempFile is temporary file we are writing to first before we do an
	// atomic rename into the destination file.
	tempFile *sftp.File

	// tempDir is the temp directory on the SFTP server.
	tempDir string

	// tempName is the name of the temporary file relative to tempDir.
	tempName string

	// writeFailed records if any writes to the tempFile failed.
	writeFailed bool
}

// ReadFrom implements io.ReaderFrom.
func (file *SFTPFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
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

// Write writes len(b) bytes from b to the SFTPFileWriter. It returns the
// number of bytes written and an error, if any. Write returns a non-nil error
// when n != len(b).
func (file *SFTPFileWriter) Write(p []byte) (n int, err error) {
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

// Close saves the contents of the SFTPFileWriter to a file on the SFTP server
// and closes the SFTPFileWriter.
func (file *SFTPFileWriter) Close() error {
	tempFilePath := path.Join(file.tempDir, file.tempName)
	destFilePath := path.Join(file.rootDir, file.name)
	defer file.sftpClient.Remove(tempFilePath)
	err := file.tempFile.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	if file.writeFailed {
		return nil
	}
	if _, ok := file.sftpClient.HasExtension("posix-rename@openssh.com"); ok {
		err := file.sftpClient.PosixRename(tempFilePath, destFilePath)
		if err != nil {
			return stacktrace.New(err)
		}
	} else {
		err := file.sftpClient.Rename(tempFilePath, destFilePath)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	return nil
}

// ReadDir implements the ReadDir FS operation for SFTPFS.
func (fsys *SFTPFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	fileInfos, err := sftpClient.ReadDir(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, stacktrace.New(err)
	}
	dirEntries := make([]fs.DirEntry, len(fileInfos))
	for i := range fileInfos {
		dirEntries[i] = fs.FileInfoToDirEntry(fileInfos[i])
	}
	return dirEntries, nil
}

// Mkdir implements the Mkdir FS operation for SFTPFS.
func (fsys *SFTPFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	return sftpClient.Mkdir(path.Join(fsys.RootDir, name))
}

// MkdirAll implements the MkdirAll FS operation for SFTPFS.
func (fsys *SFTPFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	return sftpClient.MkdirAll(path.Join(fsys.RootDir, name))
}

// Remove implements the Remove FS operation for SFTPFS.
func (fsys *SFTPFS) Remove(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	return sftpClient.Remove(path.Join(fsys.RootDir, name))
}

// RemoveAll implements the RemoveAll FS operation for STFPFS.
func (fsys *SFTPFS) RemoveAll(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	_, err = sftpClient.Stat(path.Join(fsys.RootDir, name))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
	} else {
		return nil
	}
	return sftpClient.RemoveAll(path.Join(fsys.RootDir, name))
}

// Rename implements the Rename FS operation for SFTPFS.
func (fsys *SFTPFS) Rename(oldName, newName string) error {
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
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	_, err = sftpClient.Stat(path.Join(fsys.RootDir, newName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
	} else {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrExist}
	}
	if _, ok := sftpClient.HasExtension("posix-rename@openssh.com"); ok {
		err := sftpClient.PosixRename(path.Join(fsys.RootDir, oldName), path.Join(fsys.RootDir, newName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
			}
			return stacktrace.New(err)
		}
	} else {
		err := sftpClient.Rename(path.Join(fsys.RootDir, oldName), path.Join(fsys.RootDir, newName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
			}
			return stacktrace.New(err)
		}
	}
	return nil
}

// Copy implements the Copy FS operation for SFTPFS.
func (fsys *SFTPFS) Copy(srcName, destName string) error {
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
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	_, err = sftpClient.Stat(path.Join(fsys.RootDir, destName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
	} else {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrExist}
	}
	srcFileInfo, err := sftpClient.Stat(path.Join(fsys.RootDir, srcName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "copy", Path: srcName, Err: fs.ErrNotExist}
		}
		return stacktrace.New(err)
	}
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

// Close closes all SFTP connections in the SFTPFS.
func (fsys *SFTPFS) Close() error {
	var waitGroup sync.WaitGroup
	defer waitGroup.Wait()
	for _, client := range fsys.Clients {
		client := client
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			client.sftpClient.Close()
		}()
	}
	return nil
}

// SFTPClient is a wrapper around an *sftp.Client which records the state of
// whether the *sftp.Client is disconnected.
type SFTPClient struct {
	mutex        sync.Mutex
	disconnected bool
	sftpClient   *sftp.Client
}

// Get returns the underlying *sftp.Client if it is connected, or else it
// instantiates a new one using the provided ssh.Client constructor function.
func (client *SFTPClient) Get(newSSHClient func() (*ssh.Client, error)) (*sftp.Client, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.disconnected && client.sftpClient != nil {
		return client.sftpClient, nil
	}
	sshClient, err := newSSHClient()
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, stacktrace.New(err)
	}
	client.sftpClient = sftpClient
	client.disconnected = false
	go func() {
		sshClient.Wait()
		client.mutex.Lock()
		client.disconnected = true
		client.mutex.Unlock()
	}()
	return client.sftpClient, nil
}
