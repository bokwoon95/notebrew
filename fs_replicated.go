package notebrew

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/stacktrace"
)

// ReplicatedFSConfig holds the parameters needed to construct a ReplicatedFS.
type ReplicatedFSConfig struct {
	// (Required) Leader is the primary FS that we read from and write to.
	Leader FS

	// Followers are the secondary FSes that writes are replicated to.
	Followers []FS

	// If SynchronousReplication is true, writes will be synchronously
	// replicated to the followers.
	SynchronousReplication bool

	// (Required) Logger is used for reporting errors that cannot be handled
	// and are thrown away.
	Logger *slog.Logger
}

// SFTPFS implements a writeable filesystem on a leader FS and zero or more
// follower FSes. All reads come from the leader FS, while all writes will be
// sent to the leader FS as well as the follower FSes (synchronously or
// asynchronously depending on the SynchronousReplication field).
type ReplicatedFS struct {
	// Leader is the primary FS that we read from and write to.
	Leader FS

	// Followers are the secondary FSes that writes are replicated to.
	Followers []FS

	// If SynchronousReplication is true, writes will be synchronously
	// replicated to the followers.
	SynchronousReplication bool

	// (Required) Logger is used for reporting errors that cannot be handled
	// and are thrown away.
	Logger *slog.Logger

	// ctx provides the context of all operations called on the ReplicatedFS.
	ctx context.Context

	// baseCtx is the base context of the ReplicatedFS.
	baseCtx context.Context

	// baseCtxCancel cancels the base context.
	baseCtxCancel func()

	// baseCtxWaitGroup tracks the number of asynchronous replication jobs
	// running in the background. Each async job should take in the base
	// context, and should should initiate shutdown when the base context is
	// canceled.
	baseCtxWaitGroup *sync.WaitGroup
}

// NewReplicatedFS constructs a new ReplicatedFS.
func NewReplicatedFS(config ReplicatedFSConfig) (*ReplicatedFS, error) {
	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	replicatedFS := &ReplicatedFS{
		Leader:                 config.Leader,
		Followers:              config.Followers,
		SynchronousReplication: config.SynchronousReplication,
		Logger:                 config.Logger,
		ctx:                    context.Background(),
		baseCtx:                baseCtx,
		baseCtxCancel:          baseCtxCancel,
		baseCtxWaitGroup:       &sync.WaitGroup{},
	}
	return replicatedFS, nil
}

// As calls the `As(any) bool` method on the leader FS if it exists.
func (fsys *ReplicatedFS) As(target any) bool {
	switch v := fsys.Leader.(type) {
	case interface{ As(any) bool }:
		return v.As(target)
	default:
		return false
	}
}

// WithContext returns a new FS with the given context.
func (fsys *ReplicatedFS) WithContext(ctx context.Context) FS {
	return &ReplicatedFS{
		Leader:                 fsys.Leader,
		Followers:              fsys.Followers,
		SynchronousReplication: fsys.SynchronousReplication,
		Logger:                 fsys.Logger,
		ctx:                    ctx,
		baseCtx:                fsys.baseCtx,
		baseCtxCancel:          fsys.baseCtxCancel,
		baseCtxWaitGroup:       fsys.baseCtxWaitGroup,
	}
}

// WithValues returns a new ReplicatedFS where the leader FS and each follower
// FS has `WithValues(any) FS` method called on it if it exists.
func (fsys *ReplicatedFS) WithValues(values map[string]any) FS {
	replicatedFS := &ReplicatedFS{
		Leader:                 fsys.Leader,
		Followers:              append(make([]FS, 0, len(fsys.Followers)), fsys.Followers...),
		SynchronousReplication: fsys.SynchronousReplication,
		Logger:                 fsys.Logger,
		ctx:                    fsys.ctx,
		baseCtx:                fsys.baseCtx,
		baseCtxCancel:          fsys.baseCtxCancel,
		baseCtxWaitGroup:       fsys.baseCtxWaitGroup,
	}
	if v, ok := replicatedFS.Leader.(interface {
		WithValues(map[string]any) FS
	}); ok {
		replicatedFS.Leader = v.WithValues(values)
	}
	for i, follower := range replicatedFS.Followers {
		if v, ok := follower.(interface {
			WithValues(map[string]any) FS
		}); ok {
			replicatedFS.Followers[i] = v.WithValues(values)
		}
	}
	return replicatedFS
}

// Open implements the Open FS operation for SFTPFS.
func (fsys *ReplicatedFS) Open(name string) (fs.File, error) {
	return fsys.Leader.WithContext(fsys.ctx).Open(name)
}

// Stat implements the fs.StatFS interface.
func (fsys *ReplicatedFS) Stat(name string) (fs.FileInfo, error) {
	if statFS, ok := fsys.Leader.WithContext(fsys.ctx).(fs.StatFS); ok {
		return statFS.Stat(name)
	}
	file, err := fsys.Leader.WithContext(fsys.ctx).Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

// ReplicatedFileWriter represents a writable file on a ReplicatedFS.
type ReplicatedFileWriter struct {
	// name is the name that was passed to OpenWriter().
	name string

	// perm is the permissions that was passed to OpenWriter().
	perm fs.FileMode

	// writer is the io.WriteCloser returned by the leader FS's OpenWriter().
	writer io.WriteCloser

	// writeFailed records if any writes to the writer failed.
	writeFailed bool

	// leader FS.
	leader FS

	// follower FSes.
	followers []FS

	// If synchronousReplication is true, writes will be synchronously
	// replicated to the followers.
	synchronousReplication bool

	// logger is used for reporting errors that cannot be handled and are
	// thrown away.
	logger *slog.Logger

	// ctx provides the context of all operations called on the file.
	ctx context.Context

	// baseCtx is the base context of the ReplicatedFS that created the
	// ReplicatedFileWriter.
	baseCtx context.Context

	// baseCtxWaitGroup keeps track of the asynchronous replication jobs
	// running in the background. Each async job should take in the base
	// context to be notified of when the base context is done.
	baseCtxWaitGroup *sync.WaitGroup
}

// OpenWriter implements the OpenWriter FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	writer, err := fsys.Leader.WithContext(fsys.ctx).OpenWriter(name, perm)
	if err != nil {
		return nil, err
	}
	file := &ReplicatedFileWriter{
		name:                   name,
		perm:                   perm,
		writer:                 writer,
		leader:                 fsys.Leader,
		followers:              fsys.Followers,
		synchronousReplication: fsys.SynchronousReplication,
		logger:                 fsys.Logger,
		ctx:                    fsys.ctx,
		baseCtx:                fsys.baseCtx,
		baseCtxWaitGroup:       fsys.baseCtxWaitGroup,
	}
	return file, nil
}

// Write writes len(b) bytes from b to the ReplicatedFileWriter. It returns the
// number of bytes written and an error, if any. Write returns a non-nil error
// when n != len(b).
func (file *ReplicatedFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	n, err = file.writer.Write(p)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, err
}

// Close saves the contents of the ReplicatedFileWriter to the leader FS and
// follower FSes and closes the ReplicatedFileWriter.
func (file *ReplicatedFileWriter) Close() error {
	if file.writer == nil {
		return fs.ErrClosed
	}
	defer func() {
		file.writer = nil
	}()
	err := file.writer.Close()
	if err != nil {
		return err
	}
	if file.writeFailed {
		return nil
	}
	if file.synchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range file.followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						file.logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				leaderFile, err := file.leader.WithContext(file.ctx).Open(file.name)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
				defer leaderFile.Close()
				writer, err := follower.WithContext(file.ctx).OpenWriter(file.name, file.perm)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
				defer writer.Close()
				_, err = io.Copy(writer, leaderFile)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
				err = writer.Close()
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range file.followers {
			follower := follower
			file.baseCtxWaitGroup.Add(1)
			go func() {
				defer file.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						file.logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-file.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				leaderFile, err := file.leader.WithContext(gracePeriodCtx).Open(file.name)
				if err != nil {
					file.logger.Error(err.Error())
					return
				}
				defer leaderFile.Close()
				writer, err := follower.WithContext(gracePeriodCtx).OpenWriter(file.name, file.perm)
				if err != nil {
					file.logger.Error(err.Error())
					return
				}
				defer writer.Close()
				_, err = io.Copy(writer, leaderFile)
				if err != nil {
					file.logger.Error(err.Error())
					return
				}
				err = writer.Close()
				if err != nil {
					file.logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// ReadDir implements the ReadDir FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fsys.Leader.WithContext(fsys.ctx).ReadDir(name)
}

// Mkdir implements the Mkdir FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) Mkdir(name string, perm fs.FileMode) error {
	err := fsys.Leader.WithContext(fsys.ctx).Mkdir(name, perm)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).Mkdir(name, perm)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range fsys.Followers {
			follower := follower
			fsys.baseCtxWaitGroup.Add(1)
			go func() {
				defer fsys.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-fsys.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				err := follower.WithContext(gracePeriodCtx).Mkdir(name, perm)
				if err != nil {
					fsys.Logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// MkdirAll implements the MkdirAll FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) MkdirAll(name string, perm fs.FileMode) error {
	err := fsys.Leader.WithContext(fsys.ctx).MkdirAll(name, perm)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).MkdirAll(name, perm)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range fsys.Followers {
			follower := follower
			fsys.baseCtxWaitGroup.Add(1)
			go func() {
				defer fsys.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-fsys.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				err := follower.WithContext(gracePeriodCtx).Mkdir(name, perm)
				if err != nil {
					fsys.Logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// Remove implements the Remove FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) Remove(name string) error {
	err := fsys.Leader.WithContext(fsys.ctx).Remove(name)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).Remove(name)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range fsys.Followers {
			follower := follower
			fsys.baseCtxWaitGroup.Add(1)
			go func() {
				defer fsys.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-fsys.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				err := follower.WithContext(gracePeriodCtx).Remove(name)
				if err != nil {
					fsys.Logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// RemoveAll implements the RemoveAll FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) RemoveAll(name string) error {
	err := fsys.Leader.WithContext(fsys.ctx).RemoveAll(name)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).RemoveAll(name)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range fsys.Followers {
			follower := follower
			fsys.baseCtxWaitGroup.Add(1)
			go func() {
				defer fsys.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-fsys.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				err := follower.WithContext(gracePeriodCtx).RemoveAll(name)
				if err != nil {
					fsys.Logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// Rename implements the Rename FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) Rename(oldName, newName string) error {
	err := fsys.Leader.WithContext(fsys.ctx).Rename(oldName, newName)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err = follower.WithContext(fsys.ctx).Rename(oldName, newName)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range fsys.Followers {
			follower := follower
			fsys.baseCtxWaitGroup.Add(1)
			go func() {
				defer fsys.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-fsys.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				err := follower.WithContext(gracePeriodCtx).Rename(oldName, newName)
				if err != nil {
					fsys.Logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// Copy implements the Copy FS operation for ReplicatedFS.
func (fsys *ReplicatedFS) Copy(srcName, destName string) error {
	err := fsys.Leader.WithContext(fsys.ctx).Copy(srcName, destName)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err = follower.WithContext(fsys.ctx).Copy(srcName, destName)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
	} else {
		for _, follower := range fsys.Followers {
			follower := follower
			fsys.baseCtxWaitGroup.Add(1)
			go func() {
				defer fsys.baseCtxWaitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
				defer gracePeriodCancel()
				go func() {
					timer := time.NewTimer(-1)
					defer timer.Stop()
					for {
						select {
						case <-fsys.baseCtx.Done():
							timer.Reset(time.Hour)
						case <-timer.C:
							gracePeriodCancel()
							return
						case <-gracePeriodCtx.Done():
							return
						}
					}
				}()
				err := follower.WithContext(gracePeriodCtx).Rename(srcName, destName)
				if err != nil {
					fsys.Logger.Error(err.Error())
					return
				}
			}()
		}
	}
	return nil
}

// Close initiates the shutdown of any background jobs currently synchronizing
// to the follower FSes and returns when all background jobs have completed.
func (fsys *ReplicatedFS) Close() error {
	fsys.baseCtxCancel()
	defer fsys.baseCtxWaitGroup.Wait()
	return nil
}
