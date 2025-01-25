package notebrew

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
)

var wildcardReplacer = strings.NewReplacer(`%`, `\%`, `_`, `\_`, `\`, `\\`)

var gzipReaderPool = sync.Pool{}

var gzipWriterPool = sync.Pool{
	New: func() any {
		// Use compression level 4 for best balance between space and
		// performance.
		// https://blog.klauspost.com/gzip-performance-for-go-webservers/
		gzipWriter, _ := gzip.NewWriterLevel(nil, 4)
		return gzipWriter
	},
}

// DatabaseFSConfig holds the parameters needed to construct a DatabaseFS.
type DatabaseFSConfig struct {
	// (Required) DB is the sql database.
	DB *sql.DB

	// (Required) Dialect is the database dialect. Currently, the only dialects
	// supported are "sqlite", "postgres" and "mysql".
	Dialect string

	// ErrorCode converts an error returned by a database query into a
	// dialect-specific error code.
	ErrorCode func(error) string

	// (Required) ObjectStorage is used for storage of binary objects.
	ObjectStorage ObjectStorage

	// (Required) Logger is used for reporting errors that cannot be handled
	// and are thrown away.
	Logger *slog.Logger

	// UpdateStorageUsed is called whenever the storage used by a site changes
	// (delta being the number of bytes that have been added or removed).
	// Specifically, this happens on calls to OpenWriter, Remove, RemoveAll and
	// Copy.
	UpdateStorageUsed func(ctx context.Context, siteName string, delta int64) error
}

// DatabaseFS implements a writeable filesystem using a database and an
// ObjectStorage provider.
type DatabaseFS struct {
	// DB is the sql database.
	DB *sql.DB

	// Dialect is the database dialect. Currently, the only dialects supported
	// are "sqlite", "postgres" and "mysql".
	Dialect string

	// ErrorCode converts an error returned by a database query into a
	// dialect-specific error code.
	ErrorCode func(error) string

	// ObjectStorage is used for storage of binary objects.
	ObjectStorage ObjectStorage

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// UpdateStorageUsed is called whenever the storage used by a site changes
	// (delta being the number of bytes that have been added or removed).
	// Specifically, this happens on calls to OpenWriter, Remove, RemoveAll and
	// Copy.
	UpdateStorageUsed func(ctx context.Context, siteName string, delta int64) error

	// ctx provides the context of all operations called on the DatabaseFS.
	ctx context.Context

	// values is a key-value store containing values used by some filesystem
	// operations. Currently, the following values are recognized:
	//
	// - "modTime"      => time.Time (sets the modTime for files created by OpenWriter/Mkdir/MkdirAll)
	//
	// - "creationTime" => time.Time (sets the creationTime for files created by OpenWriter/Mkdir/MkdirAll)
	//
	// - "caption"      => string    (sets the caption for images created by OpenWriter)
	//
	// - "httprange"    => string    (value of the HTTP Range header passed to GetObject, if the underlying file is in ObjectStorage)
	values map[string]any
}

// NewDatabaseFS constructs a new DatabaseFS.
func NewDatabaseFS(config DatabaseFSConfig) (*DatabaseFS, error) {
	databaseFS := &DatabaseFS{
		DB:                config.DB,
		Dialect:           config.Dialect,
		ErrorCode:         config.ErrorCode,
		ObjectStorage:     config.ObjectStorage,
		Logger:            config.Logger,
		UpdateStorageUsed: config.UpdateStorageUsed,
		ctx:               context.Background(),
	}
	return databaseFS, nil
}

// As writes the current databaseFS into the target if it is a valid DatabaseFS
// pointer.
func (fsys *DatabaseFS) As(target any) bool {
	switch target := target.(type) {
	case *DatabaseFS:
		*target = *fsys
		return true
	case **DatabaseFS:
		*target = fsys
		return true
	default:
		return false
	}
}

// WithContext returns a new FS with the given context.
func (fsys *DatabaseFS) WithContext(ctx context.Context) FS {
	return &DatabaseFS{
		DB:                fsys.DB,
		Dialect:           fsys.Dialect,
		ErrorCode:         fsys.ErrorCode,
		ObjectStorage:     fsys.ObjectStorage,
		Logger:            fsys.Logger,
		UpdateStorageUsed: fsys.UpdateStorageUsed,
		ctx:               ctx,
		values:            fsys.values,
	}
}

// WithValues returns a new FS with the given values.
//
// Currently, the following values are recognized:
//
// - "modTime"      => time.Time (sets the modTime for files created by OpenWriter/Mkdir/MkdirAll)
//
// - "creationTime" => time.Time (sets the creationTime for files created by OpenWriter/Mkdir/MkdirAll)
//
// - "caption"      => string    (sets the caption for images created by OpenWriter)
//
// - "httprange"    => string    (value of the HTTP Range header passed to GetObject, if the underlying file is in ObjectStorage)
//
// These values will apply to *all* filesystem operations, so if you only want
// to set the modTime or creationTime for a specific file you will have to
// create a new instance of a DatabaseFS using WithValues(), create that file,
// then throw the DatabaseFS instance away.
func (fsys *DatabaseFS) WithValues(values map[string]any) FS {
	return &DatabaseFS{
		DB:                fsys.DB,
		Dialect:           fsys.Dialect,
		ErrorCode:         fsys.ErrorCode,
		ObjectStorage:     fsys.ObjectStorage,
		Logger:            fsys.Logger,
		UpdateStorageUsed: fsys.UpdateStorageUsed,
		ctx:               fsys.ctx,
		values:            values,
	}
}

// DatabaseFileInfo describes a file returned by DatabaseFS.
type DatabaseFileInfo struct {
	FileID       ID
	FilePath     string
	isDir        bool
	size         int64
	modTime      time.Time
	CreationTime time.Time
}

// DatabaseFile represents a readable instance of a file returned by
// DatabaseFS.
type DatabaseFile struct {
	// ctx provides the context of all operations called on the DatabaseFile.
	ctx context.Context

	// FileType of the DatabaseFile.
	fileType FileType

	// FileInfo of the DatabaseFile.
	info *DatabaseFileInfo

	// Whether the file is fulltext indexed.
	isFulltextIndexed bool

	// buf holds the raw bytes of the DatabaseFile. It may be gzipped,
	// depending on whether the file is gzippable and is not fulltext indexed.
	buf *bytes.Buffer

	// If the file is gzippable and is not fulltext indexed, the raw bytes of
	// the file are gzipped and Read operations should read from the gzipReader
	// instead (which in turn reads from the raw bytes inside the buffer).
	gzipReader *gzip.Reader

	// If the file is an object, it is not stored by the database but rather by
	// the filesystem's ObjectStorage provider. In which case, readCloser would
	// be a reference to the object.
	readCloser io.ReadCloser
}

// Open implements the Open FS operation for DatabaseFS.
func (fsys *DatabaseFS) Open(name string) (fs.File, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	// If we are opening the root dir, return a hardcoded DatabaseFile
	// representing the root (the root directory is not stored in a database
	// FS, it is an implicit construct).
	if name == "." {
		file := &DatabaseFile{
			ctx:  fsys.ctx,
			info: &DatabaseFileInfo{FilePath: ".", isDir: true},
		}
		return file, nil
	}
	var fileType FileType
	if ext := path.Ext(name); ext != "" {
		fileType = AllowedFileTypes[strings.ToLower(ext)]
	}
	file, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *DatabaseFile {
		file := &DatabaseFile{
			ctx:      fsys.ctx,
			fileType: fileType,
			info:     &DatabaseFileInfo{},
		}
		file.info.FileID = row.UUID("file_id")
		file.info.FilePath = row.String("file_path")
		file.info.isDir = row.Bool("is_dir")
		file.info.size = row.Int64("size")
		file.info.modTime = row.Time("mod_time")
		file.info.CreationTime = row.Time("creation_time")
		if !fileType.Has(AttributeObject) {
			file.buf = bytes.NewBuffer(row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "COALESCE(text, data)"))
		}
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil, stacktrace.New(err)
	}
	file.isFulltextIndexed = IsFulltextIndexed(file.info.FilePath)
	if fileType.Has(AttributeObject) {
		objectStorage := fsys.ObjectStorage
		if v, ok := objectStorage.(interface {
			WithValues(map[string]any) ObjectStorage
		}); ok {
			objectStorage = v.WithValues(fsys.values)
		}
		file.readCloser, err = objectStorage.Get(file.ctx, file.info.FileID.String()+path.Ext(file.info.FilePath))
		if err != nil {
			return nil, stacktrace.New(err)
		}
		// Writing an *os.File to net/http's ResponseWriter is fast on Linux
		// because it uses the low-level sendfile(2) system call. If the
		// underlying readCloser is an *os.File, return it directly so that
		// static files can be served much faster.
		// https://www.reddit.com/r/golang/comments/b9ewko/rob_pike_discovers_sendfile2_old_but_informative/hphp294/
		// https://github.com/golang/go/blob/master/src/internal/poll/sendfile_linux.go
		// https://github.com/golang/go/blob/f229e7031a6efb2f23241b5da000c3b3203081d6/src/io/io.go#L404
		// https://github.com/golang/go/blob/f229e7031a6efb2f23241b5da000c3b3203081d6/src/net/tcpsock_posix.go#L47
		if file, ok := file.readCloser.(*os.File); ok {
			return file, nil
		}
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			// Do NOT pass file.buf directly to gzip.Reader or it will do an
			// unwanted read from the buffer! We want to keep file.buf unread
			// in case someone wants to reach directly into it and pull out the
			// raw gzipped bytes.
			r := bytes.NewReader(file.buf.Bytes())
			file.gzipReader, _ = gzipReaderPool.Get().(*gzip.Reader)
			if file.gzipReader == nil {
				file.gzipReader, err = gzip.NewReader(r)
				if err != nil {
					return nil, stacktrace.New(err)
				}
			} else {
				err = file.gzipReader.Reset(r)
				if err != nil {
					return nil, stacktrace.New(err)
				}
			}
		}
	}
	return file, nil
}

// Stat implements the fs.StatFS interface.
func (fsys *DatabaseFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &DatabaseFileInfo{FilePath: ".", isDir: true}, nil
	}
	fileInfo, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *DatabaseFileInfo {
		return &DatabaseFileInfo{
			FileID:       row.UUID("file_id"),
			FilePath:     row.String("file_path"),
			isDir:        row.Bool("is_dir"),
			size:         row.Int64("size"),
			modTime:      row.Time("mod_time"),
			CreationTime: row.Time("creation_time"),
		}
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
		}
		return nil, stacktrace.New(err)
	}
	return fileInfo, nil
}

// Base name of the file.
func (fileInfo *DatabaseFileInfo) Name() string { return path.Base(fileInfo.FilePath) }

// Size of the file in bytes.
func (fileInfo *DatabaseFileInfo) Size() int64 { return fileInfo.size }

// Modification time.
func (fileInfo *DatabaseFileInfo) ModTime() time.Time { return fileInfo.modTime }

// Whether the file is a directory.
func (fileInfo *DatabaseFileInfo) IsDir() bool { return fileInfo.isDir }

// Sys always returns nil.
func (fileInfo *DatabaseFileInfo) Sys() any { return nil }

// Type bits (needed to implement fs.DirEntry).
func (fileInfo *DatabaseFileInfo) Type() fs.FileMode { return fileInfo.Mode().Type() }

// Returns the file info (needed to implement fs.DirEntry).
func (fileInfo *DatabaseFileInfo) Info() (fs.FileInfo, error) { return fileInfo, nil }

// File mode bits.
func (fileInfo *DatabaseFileInfo) Mode() fs.FileMode {
	if fileInfo.isDir {
		return fs.ModeDir
	}
	return 0
}

// Stat returns the file info describing the file.
func (file *DatabaseFile) Stat() (fs.FileInfo, error) {
	return file.info, nil
}

// Read reads up to len(b) bytes from the DatabaseFile and stores them in b. It
// returns the number of bytes read and any error encountered. At end of file,
// Read returns 0, io.EOF.
func (file *DatabaseFile) Read(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		return 0, stacktrace.New(err)
	}
	if file.info.isDir {
		return 0, &fs.PathError{Op: "read", Path: file.info.FilePath, Err: syscall.EISDIR}
	}
	if file.fileType.Has(AttributeObject) {
		return file.readCloser.Read(p)
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			return file.gzipReader.Read(p)
		} else {
			return file.buf.Read(p)
		}
	}
}

// Close closes the DatabaseFile from reading.
func (file *DatabaseFile) Close() error {
	if file.info.isDir {
		return nil
	}
	if file.fileType.Has(AttributeObject) {
		if file.readCloser == nil {
			return fs.ErrClosed
		}
		err := file.readCloser.Close()
		if err != nil {
			return err
		}
		file.readCloser = nil
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			if file.gzipReader == nil {
				return fs.ErrClosed
			}
			file.gzipReader.Reset(bytes.NewReader(nil))
			gzipReaderPool.Put(file.gzipReader)
			file.gzipReader = nil
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		} else {
			if file.buf == nil {
				return fs.ErrClosed
			}
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		}
	}
	return nil
}

// DatabaseFileWriter represents a writable file on a DatabaseFS.
type DatabaseFileWriter struct {
	// database connection.
	db *sql.DB

	// dialect of the database.
	dialect string

	// objectStorage is only used for deleting the object from object storage
	// in case the database write fails (we don't want a bunch of partial
	// writes to bloat the object storage with objects that have no database
	// record).
	objectStorage ObjectStorage

	// logger is used for reporting errors that cannot be handled and are
	// thrown away.
	logger *slog.Logger

	// updateStorageUsed is used to update the storage used by the site after
	// the file has been fully written.
	updateStorageUsed func(ctx context.Context, siteName string, delta int64) error

	// ctx provides the context of all operations called on the DatabaseFileWriter.
	ctx context.Context

	// fileType of file.
	fileType FileType

	// Whether the file is fulltext indexed.
	isFulltextIndexed bool

	// Whether we are writing to an existing file or creating a new one.
	exists bool

	// fileID of the file.
	fileID ID

	// fileID of the file's parent.
	parentID ID

	// filePath of the file.
	filePath string

	// The file's initial size (if it exists).
	initialSize int64

	// The file's size after being written.
	size int64

	// buf holds the raw bytes of the DatabaseFileWriter. It may have first
	// gone through the gzipWriter, depending on whether the file is gzippable
	// and is not fulltext indexed.
	buf *bytes.Buffer

	// If the file is gzippable and is not fulltext indexed, all writes to the
	// file first go through the gzipWriter before going into the buffer.
	gzipWriter *gzip.Writer

	// The value of the modTime to be set for the file.
	modTime time.Time

	// The value of the creationTime to be set for the file.
	creationTime time.Time

	// The value of the caption to be set for the image file. Images are stored
	// in object storage so we can use the database's text field for storing
	// captions.
	caption string

	// objectStorageWriter writes to the object in object storage.
	objectStorageWriter *io.PipeWriter

	// objectStorageResult holds the result of writing to the object in object
	// storage.
	objectStorageResult chan error

	// writeFailed records if any writes to the DatabaseFileWriter failed.
	writeFailed bool
}

// OpenWriter implements the OpenWriter FS operation for DatabaseFS.
func (fsys *DatabaseFS) OpenWriter(name string, _ fs.FileMode) (io.WriteCloser, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
	}
	var fileType FileType
	if ext := path.Ext(name); ext != "" {
		fileType = AllowedFileTypes[strings.ToLower(ext)]
	}
	now := time.Now().UTC()
	modTime := now
	if value, ok := fsys.values["modTime"].(time.Time); ok {
		modTime = value
	}
	creationTime := now
	if value, ok := fsys.values["creationTime"].(time.Time); ok {
		creationTime = value
	}
	caption := ""
	if value, ok := fsys.values["caption"].(string); ok {
		caption = value
	}
	file := &DatabaseFileWriter{
		db:                fsys.DB,
		dialect:           fsys.Dialect,
		objectStorage:     fsys.ObjectStorage,
		logger:            fsys.Logger,
		updateStorageUsed: fsys.UpdateStorageUsed,
		ctx:               fsys.ctx,
		fileType:          fileType,
		isFulltextIndexed: IsFulltextIndexed(name),
		filePath:          name,
		modTime:           modTime,
		creationTime:      creationTime,
		caption:           caption,
	}
	// Get the fileID as well as the parentID (if the file exists).
	parentDir := path.Dir(file.filePath)
	if parentDir == "." {
		// If parentDir is the root directory ".", it doesn't exist in the
		// database (it exists implicitly) so we don't have to fetch the
		// parentID.
		result, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID ID
			isDir  bool
			size   int64
		}) {
			result.fileID = row.UUID("file_id")
			result.isDir = row.Bool("is_dir")
			result.size = row.Int64("size")
			return result
		})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, stacktrace.New(err)
			}
			file.fileID = NewID()
		} else {
			if result.isDir {
				return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
			}
			file.exists = true
			file.fileID = result.fileID
			file.initialSize = result.size
		}
	} else {
		results, err := sq.FetchAll(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path IN ({parentDir}, {filePath})",
			Values: []any{
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID   ID
			filePath string
			isDir    bool
			size     int64
		}) {
			result.fileID = row.UUID("file_id")
			result.filePath = row.String("file_path")
			result.isDir = row.Bool("is_dir")
			result.size = row.Int64("size")
			return result
		})
		if err != nil {
			return nil, stacktrace.New(err)
		}
		for _, result := range results {
			switch result.filePath {
			case name:
				if result.isDir {
					return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
				}
				file.exists = true
				file.fileID = result.fileID
				file.initialSize = result.size
			case parentDir:
				if !result.isDir {
					return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.ENOTDIR}
				}
				file.parentID = result.fileID
			}
		}
		if file.parentID.IsZero() {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
		if file.fileID.IsZero() {
			file.fileID = NewID()
		}
	}
	// Prepare the underlying writers.
	if fileType.Has(AttributeObject) {
		pipeReader, pipeWriter := io.Pipe()
		file.objectStorageWriter = pipeWriter
		file.objectStorageResult = make(chan error, 1)
		go func() {
			defer stacktrace.RecoverPanic(&err)
			file.objectStorageResult <- fsys.ObjectStorage.Put(file.ctx, file.fileID.String()+path.Ext(file.filePath), pipeReader)
		}()
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			file.buf = bufPool.Get().(*bytes.Buffer)
			file.gzipWriter = gzipWriterPool.Get().(*gzip.Writer)
			file.gzipWriter.Reset(file.buf)
		} else {
			file.buf = bufPool.Get().(*bytes.Buffer)
		}
	}
	return file, nil
}

// Write writes len(b) bytes from b to the DatabaseFileWriter. It returns the
// number of bytes written and an error, if any. Write returns a non-nil error
// when n != len(b).
func (file *DatabaseFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if file.fileType.Has(AttributeObject) {
		n, err = file.objectStorageWriter.Write(p)
		if err != nil {
			file.writeFailed = true
			return n, stacktrace.New(err)
		}
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			n, err = file.gzipWriter.Write(p)
			if err != nil {
				file.writeFailed = true
				return n, stacktrace.New(err)
			}
		} else {
			n, err = file.buf.Write(p)
			if err != nil {
				file.writeFailed = true
				return n, stacktrace.New(err)
			}
		}
	}
	file.size += int64(n)
	return n, nil
}

// ReadFrom implements io.ReaderFrom.
func (file *DatabaseFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, stacktrace.New(err)
	}
	if file.fileType.Has(AttributeObject) {
		n, err = io.Copy(file.objectStorageWriter, r)
		if err != nil {
			file.writeFailed = true
			return 0, stacktrace.New(err)
		}
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			n, err = io.Copy(file.gzipWriter, r)
			if err != nil {
				file.writeFailed = true
				return 0, stacktrace.New(err)
			}
		} else {
			n, err = file.buf.ReadFrom(r)
			if err != nil {
				file.writeFailed = true
				return 0, stacktrace.New(err)
			}
		}
	}
	file.size += int64(n)
	return n, nil
}

// Close saves the contents of the DatabaseFileWriter into the database and
// closes the DatabaseFileWriter.
func (file *DatabaseFileWriter) Close() error {
	if file.fileType.Has(AttributeObject) {
		if file.objectStorageWriter == nil {
			return fs.ErrClosed
		}
		file.objectStorageWriter.Close()
		file.objectStorageWriter = nil
		err := <-file.objectStorageResult
		if err != nil {
			return stacktrace.New(err)
		}
	} else {
		if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
			if file.gzipWriter == nil {
				return fs.ErrClosed
			}
			err := file.gzipWriter.Close()
			if err != nil {
				return stacktrace.New(err)
			}
			defer func() {
				file.gzipWriter.Reset(io.Discard)
				gzipWriterPool.Put(file.gzipWriter)
				file.gzipWriter = nil
				if file.buf.Cap() <= maxPoolableBufferCapacity {
					file.buf.Reset()
					bufPool.Put(file.buf)
				}
				file.buf = nil
			}()
		} else {
			if file.buf == nil {
				return fs.ErrClosed
			}
			defer func() {
				if file.buf.Cap() <= maxPoolableBufferCapacity {
					file.buf.Reset()
					bufPool.Put(file.buf)
				}
				file.buf = nil
			}()
		}
	}
	if file.writeFailed {
		return nil
	}

	if file.exists {
		// If file exists, just have to update the file entry in the database.
		if file.fileType.Has(AttributeObject) {
			var text sql.NullString
			if (file.fileType.Has(AttributeImg) || file.fileType.Has(AttributeVideo)) && file.caption != "" {
				text = sql.NullString{String: file.caption, Valid: true}
			}
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format:  "UPDATE files SET text = {text}, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.Param("text", text),
					sq.Int64Param("size", file.size),
					sq.TimeParam("modTime", file.modTime),
					sq.UUIDParam("fileID", file.fileID),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		} else {
			if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = NULL, data = {data}, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("data", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
						sq.TimeParam("modTime", file.modTime),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
			} else {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = {text}, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("text", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
						sq.TimeParam("modTime", file.modTime),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
			}
		}
	} else {
		// If we reach here it means file doesn't exist. Insert a new file entry
		// into the database.
		if file.fileType.Has(AttributeObject) {
			var text sql.NullString
			if (file.fileType.Has(AttributeImg) || file.fileType.Has(AttributeVideo)) && file.caption != "" {
				text = sql.NullString{String: file.caption, Valid: true}
			}
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, text, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {text}, {modTime}, {creationTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", file.fileID),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.Param("text", text),
					sq.TimeParam("modTime", file.modTime),
					sq.TimeParam("creationTime", file.creationTime),
				},
			})
			if err != nil {
				go func() {
					defer stacktrace.RecoverPanic(&err)
					// This is a cleanup operation - don't pass in the file.ctx
					// because file.ctx may be canceled and prevent the
					// cleanup.
					err := file.objectStorage.Delete(context.Background(), file.fileID.String()+path.Ext(file.filePath))
					if err != nil {
						file.logger.Error(stacktrace.New(err).Error())
					}
				}()
				return err
			}
		} else {
			if file.fileType.Has(AttributeGzippable) && !file.isFulltextIndexed {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format: "INSERT INTO files (file_id, parent_id, file_path, size, data, mod_time, creation_time, is_dir)" +
						" VALUES ({fileID}, {parentID}, {filePath}, {size}, {data}, {modTime}, {creationTime}, FALSE)",
					Values: []any{
						sq.UUIDParam("fileID", file.fileID),
						sq.UUIDParam("parentID", file.parentID),
						sq.StringParam("filePath", file.filePath),
						sq.Int64Param("size", file.size),
						sq.BytesParam("data", file.buf.Bytes()),
						sq.TimeParam("modTime", file.modTime),
						sq.TimeParam("creationTime", file.creationTime),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
			} else {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format: "INSERT INTO files (file_id, parent_id, file_path, size, text, mod_time, creation_time, is_dir)" +
						" VALUES ({fileID}, {parentID}, {filePath}, {size}, {text}, {modTime}, {creationTime}, FALSE)",
					Values: []any{
						sq.UUIDParam("fileID", file.fileID),
						sq.UUIDParam("parentID", file.parentID),
						sq.StringParam("filePath", file.filePath),
						sq.Int64Param("size", file.size),
						sq.BytesParam("text", file.buf.Bytes()),
						sq.TimeParam("modTime", file.modTime),
						sq.TimeParam("creationTime", file.creationTime),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
			}
		}
	}
	delta := file.size - file.initialSize
	if delta == 0 {
		return nil
	}
	// Update the site's storage used.
	if file.updateStorageUsed != nil {
		var sitePrefix string
		head, _, _ := strings.Cut(file.filePath, "/")
		if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
			sitePrefix = head
		}
		err := file.updateStorageUsed(file.ctx, strings.TrimPrefix(sitePrefix, "@"), delta)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	// Update the size of all ancestor directories.
	ancestors := make([]string, 0, strings.Count(file.filePath, "/"))
	for dir := path.Dir(file.filePath); dir != "."; dir = path.Dir(dir) {
		ancestors = append(ancestors, dir)
	}
	if len(ancestors) > 0 {
		_, err := sq.Exec(file.ctx, file.db, sq.Query{
			Dialect: file.dialect,
			Format: "UPDATE files" +
				" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
				" WHERE file_path IN ({ancestors})" +
				" AND is_dir",
			Values: []any{
				sq.Int64Param("delta", delta),
				sq.Param("ancestors", ancestors),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	}
	return nil
}

// ReadDir implements the ReadDir FS operation for DatabaseFS.
func (fsys *DatabaseFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	// NOTE: strictly speaking we should return some kind of error
	// (syscall.ENOTDIR/fs.ErrNotExist) if name is not a dir, but that requires
	// an additional database call and I'm not comfortable with that. For now
	// we will just return zero entries and no error if the user calls
	// ReadDir() on a file. This may change in the future if notebrew needs to
	// differentiate calling ReadDir on a file vs on a directory.
	var condition sq.Expression
	if name == "." {
		condition = sq.Expr("parent_id IS NULL")
	} else {
		condition = sq.Expr("parent_id = (SELECT file_id FROM files WHERE file_path = {})", name)
	}
	dirEntries, err := sq.FetchAll(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE {condition} ORDER BY file_path",
		Values: []any{
			sq.Param("condition", condition),
		},
	}, func(row *sq.Row) fs.DirEntry {
		file := &DatabaseFileInfo{}
		file.FileID = row.UUID("file_id")
		file.FilePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.size = row.Int64("size")
		file.modTime = row.Time("mod_time")
		file.CreationTime = row.Time("creation_time")
		return file
	})
	if err != nil {
		return nil, stacktrace.New(err)
	}
	return dirEntries, nil
}

// Mkdir implements the Mkdir FS operation for DatabaseFS.
func (fsys *DatabaseFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	now := time.Now().UTC()
	modTime := now
	if value, ok := fsys.values["modTime"].(time.Time); ok {
		modTime = value
	}
	creationTime := now
	if value, ok := fsys.values["creationTime"].(time.Time); ok {
		creationTime = value
	}
	parentDir := path.Dir(name)
	if parentDir == "." {
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {creationTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", name),
				sq.TimeParam("modTime", modTime),
				sq.TimeParam("creationTime", creationTime),
			},
		})
		if err != nil {
			if fsys.ErrorCode == nil {
				return stacktrace.New(err)
			}
			errcode := fsys.ErrorCode(err)
			if IsKeyViolation(fsys.Dialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return stacktrace.New(err)
		}
	} else {
		parentID, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {parentDir}",
			Values: []any{
				sq.StringParam("parentDir", parentDir),
			},
		}, func(row *sq.Row) ID {
			return row.UUID("file_id")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrNotExist}
			}
			return stacktrace.New(err)
		}
		_, err = sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {parentID}, {filePath}, {modTime}, {creationTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.UUIDParam("parentID", parentID),
				sq.StringParam("filePath", name),
				sq.TimeParam("modTime", modTime),
				sq.TimeParam("creationTime", creationTime),
			},
		})
		if err != nil {
			if fsys.ErrorCode == nil {
				return stacktrace.New(err)
			}
			errcode := fsys.ErrorCode(err)
			if IsKeyViolation(fsys.Dialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return stacktrace.New(err)
		}
	}
	return nil
}

// MkdirAll implements the MkdirAll FS operation for DatabaseFS.
func (fsys *DatabaseFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	tx, err := fsys.DB.BeginTx(fsys.ctx, nil)
	if err != nil {
		return stacktrace.New(err)
	}
	defer tx.Rollback()

	// Insert the top level directory (no parent), ignoring duplicates.
	now := time.Now().UTC()
	modTime := now
	if value, ok := fsys.values["modTime"].(time.Time); ok {
		modTime = value
	}
	creationTime := now
	if value, ok := fsys.values["creationTime"].(time.Time); ok {
		creationTime = value
	}
	segments := strings.Split(name, "/")
	switch fsys.Dialect {
	case "sqlite", "postgres":
		_, err := sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {creationTime}, TRUE)" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.TimeParam("modTime", modTime),
				sq.TimeParam("creationTime", creationTime),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	case "mysql":
		_, err := sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {creationTime}, TRUE)" +
				" ON DUPLICATE KEY UPDATE file_id = file_id",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.TimeParam("modTime", modTime),
				sq.TimeParam("creationTime", creationTime),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.Dialect)
	}

	// Insert the rest of the directories, ignoring duplicates.
	if len(segments) > 1 {
		var preparedExec *sq.PreparedExec
		switch fsys.Dialect {
		case "sqlite", "postgres":
			preparedExec, err = sq.PrepareExec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {creationTime}, TRUE)" +
					" ON CONFLICT DO NOTHING",
				Values: []any{
					sq.Param("fileID", nil),
					sq.Param("parentDir", nil),
					sq.Param("filePath", nil),
					sq.Param("modTime", nil),
					sq.Param("creationTime", nil),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		case "mysql":
			preparedExec, err = sq.PrepareExec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {creationTime}, TRUE)" +
					" ON DUPLICATE KEY UPDATE file_id = file_id",
				Values: []any{
					sq.Param("fileID", nil),
					sq.Param("parentDir", nil),
					sq.Param("filePath", nil),
					sq.Param("modTime", nil),
					sq.Param("creationTime", nil),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		default:
			return stacktrace.New(fmt.Errorf("unsupported dialect %q", fsys.Dialect))
		}
		defer preparedExec.Close()
		for i := 1; i < len(segments); i++ {
			parentDir := path.Join(segments[:i]...)
			filePath := path.Join(segments[:i+1]...)
			_, err := preparedExec.Exec(fsys.ctx,
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", filePath),
				sq.TimeParam("modTime", modTime),
				sq.TimeParam("creationTime", creationTime),
			)
			if err != nil {
				return stacktrace.New(err)
			}
		}
		err = preparedExec.Close()
		if err != nil {
			return stacktrace.New(err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

// Remove implements the Remove FS operation for DatabaseFS.
func (fsys *DatabaseFS) Remove(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	file, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (file struct {
		fileID      ID
		filePath    string
		isDir       bool
		hasChildren bool
	}) {
		file.fileID = row.UUID("file_id")
		file.filePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.hasChildren = row.Bool("EXISTS (SELECT 1 FROM files WHERE file_path LIKE {pattern} ESCAPE '\\')", sq.StringParam("pattern", wildcardReplacer.Replace(name)+"/%"))
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
		}
		return stacktrace.New(err)
	}
	if file.hasChildren {
		return &fs.PathError{Op: "remove", Path: name, Err: syscall.ENOTEMPTY}
	}
	// Delete the underlying object from object storage.
	fileType := AllowedFileTypes[strings.ToLower(path.Ext(name))]
	if fileType.Has(AttributeObject) {
		err = fsys.ObjectStorage.Delete(fsys.ctx, file.fileID.String()+path.Ext(file.filePath))
		if err != nil {
			fsys.Logger.Error(stacktrace.New(err).Error())
		}
	}
	// Delete any pinned files.
	_, err = sq.Exec(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "DELETE FROM pinned_file WHERE (SELECT file_id FROM files WHERE file_path = {name}) IN (parent_id, file_id)",
		Values: []any{
			sq.StringParam("name", name),
		},
	})
	if err != nil {
		return stacktrace.New(err)
	}
	// Get the size of the file being removed.
	size, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) int64 {
		return row.Int64("CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END")
	})
	if err != nil {
		return stacktrace.New(err)
	}
	// Delete the file.
	_, err = sq.Exec(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "DELETE FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	})
	if err != nil {
		return stacktrace.New(err)
	}
	if file.isDir {
		return nil
	}
	// Subtract the file's size from the site's storage used.
	if fsys.UpdateStorageUsed != nil {
		var sitePrefix string
		head, _, _ := strings.Cut(name, "/")
		if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
			sitePrefix = head
		}
		err := fsys.UpdateStorageUsed(fsys.ctx, strings.TrimPrefix(sitePrefix, "@"), -size)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	// Subtract the file size from all ancestor directories.
	ancestors := make([]string, 0, strings.Count(name, "/"))
	for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
		ancestors = append(ancestors, dir)
	}
	if len(ancestors) > 0 {
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "UPDATE files" +
				" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
				" WHERE file_path IN ({ancestors})" +
				" AND is_dir",
			Values: []any{
				sq.Int64Param("delta", -size),
				sq.Param("ancestors", ancestors),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	}
	return nil
}

// RemoveAll implements the RemoveAll FS operation for DatabaseFS.
func (fsys *DatabaseFS) RemoveAll(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	// Delete the underlying objects from object storage.
	pattern := wildcardReplacer.Replace(name) + "/%"
	extFilter := sq.Expr("1 <> 1")
	if len(objectExts) > 0 {
		var b strings.Builder
		args := make([]any, 0, len(objectExts))
		b.WriteString("(")
		for i, ext := range objectExts {
			if i > 0 {
				b.WriteString(" OR ")
			}
			b.WriteString("file_path LIKE {} ESCAPE '\\'")
			args = append(args, "%"+wildcardReplacer.Replace(ext))
		}
		b.WriteString(")")
		extFilter = sq.Expr(b.String(), args...)
	}
	cursor, err := sq.FetchCursor(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE (file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\')" +
			" AND NOT is_dir" +
			" AND {extFilter}",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
			sq.Param("extFilter", extFilter),
		},
	}, func(row *sq.Row) (file struct {
		fileID   ID
		filePath string
	}) {
		file.fileID = row.UUID("file_id")
		file.filePath = row.String("file_path")
		return file
	})
	if err != nil {
		return stacktrace.New(err)
	}
	defer cursor.Close()
	var waitGroup sync.WaitGroup
	for cursor.Next() {
		file, err := cursor.Result()
		if err != nil {
			return stacktrace.New(err)
		}
		waitGroup.Add(1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			defer waitGroup.Done()
			err := fsys.ObjectStorage.Delete(fsys.ctx, file.fileID.String()+path.Ext(file.filePath))
			if err != nil {
				fsys.Logger.Error(stacktrace.New(err).Error())
			}
		}()
	}
	err = cursor.Close()
	if err != nil {
		return err
	}
	waitGroup.Wait()
	// Delete any pinned files.
	_, err = sq.Exec(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format: "DELETE FROM pinned_file WHERE EXISTS (" +
			"SELECT 1" +
			" FROM files" +
			" WHERE (file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\') " +
			" AND files.file_id IN (pinned_file.parent_id, pinned_file.file_id)" +
			")",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	})
	// Get the total size of the files being removed.
	totalSize, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	}, func(row *sq.Row) int64 {
		return row.Int64("sum(CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END)")
	})
	if err != nil {
		return stacktrace.New(err)
	}
	// Delete the files.
	_, err = sq.Exec(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "DELETE FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	})
	if err != nil {
		return stacktrace.New(err)
	}
	// Subtract the files' total size from the site's storage used.
	if fsys.UpdateStorageUsed != nil {
		var sitePrefix string
		head, _, _ := strings.Cut(name, "/")
		if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
			sitePrefix = head
		}
		err := fsys.UpdateStorageUsed(fsys.ctx, strings.TrimPrefix(sitePrefix, "@"), -totalSize)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	// Subtract the files' total size from all ancestor directories.
	ancestors := make([]string, 0, strings.Count(name, "/"))
	for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
		ancestors = append(ancestors, dir)
	}
	if len(ancestors) > 0 {
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "UPDATE files" +
				" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
				" WHERE file_path IN ({ancestors})" +
				" AND is_dir",
			Values: []any{
				sq.Int64Param("delta", -totalSize),
				sq.Param("ancestors", ancestors),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	}
	return nil
}

// Rename implements the Rename FS operation for DatabaseFS.
func (fsys *DatabaseFS) Rename(oldName, newName string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(oldName) || strings.Contains(oldName, "\\") {
		return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newName) || strings.Contains(newName, "\\") {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrInvalid}
	}
	// newName must not exist.
	exists, err := sq.FetchExists(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT 1 FROM files WHERE file_path = {newName}",
		Values: []any{
			sq.StringParam("newName", newName),
		},
	})
	if exists {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrExist}
	}
	// totalSize of the files being renamed/moved.
	var totalSize int64
	tx, err := fsys.DB.BeginTx(fsys.ctx, nil)
	if err != nil {
		return stacktrace.New(err)
	}
	defer tx.Rollback()
	switch fsys.Dialect {
	case "sqlite", "postgres":
		var reparent sq.Expression
		if path.Dir(oldName) != path.Dir(newName) {
			reparent = sq.Expr(", parent_id = (SELECT file_id FROM files WHERE file_path = {})", path.Dir(newName))
		}
		// Rename the file, retrieving the file size at the same time.
		result, err := sq.FetchOne(fsys.ctx, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "UPDATE files SET file_path = {newName}, mod_time = {modTime}{reparent} WHERE file_path = {oldName} RETURNING {*}",
			Values: []any{
				sq.StringParam("newName", newName),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.Param("reparent", reparent),
				sq.StringParam("oldName", oldName),
			},
		}, func(row *sq.Row) (result struct {
			isDir bool
			size  int64
		}) {
			result.isDir = row.Bool("is_dir")
			result.size = row.Int64("CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
			}
			return stacktrace.New(err)
		}
		if result.isDir {
			// If the file is a directory, rename the directory prefix for all
			// descendants. Retrieve the descendants' total size at the same
			// time.
			cursor, err := sq.FetchCursor(fsys.ctx, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\' RETURNING {*}",
				Values: []any{
					sq.Param("filePath", sq.Expr("{} || substring(file_path, {})", newName, utf8.RuneCountInString(oldName)+1)),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("pattern", wildcardReplacer.Replace(oldName)+"/%"),
				},
			}, func(row *sq.Row) int64 {
				return row.Int64("CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END")
			})
			if err != nil {
				return stacktrace.New(err)
			}
			defer cursor.Close()
			for cursor.Next() {
				size, err := cursor.Result()
				if err != nil {
					return stacktrace.New(err)
				}
				totalSize += size
			}
			err = cursor.Close()
			if err != nil {
				return stacktrace.New(err)
			}
		} else {
			totalSize = result.size
			if path.Ext(oldName) != path.Ext(newName) {
				return fmt.Errorf("file extension cannot be changed")
			}
		}
	case "mysql":
		// Retrieve the file size.
		result, err := sq.FetchOne(fsys.ctx, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {oldName}",
			Values: []any{
				sq.StringParam("oldName", oldName),
			},
		}, func(row *sq.Row) (result struct {
			isDir bool
			size  int64
		}) {
			result.isDir = row.Bool("is_dir")
			result.size = row.Int64("CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
			}
			return stacktrace.New(err)
		}
		// Rename the file.
		var reparent sq.Expression
		if path.Dir(oldName) != path.Dir(newName) {
			reparent = sq.Expr(", parent_id = (SELECT file_id FROM files WHERE file_path = {})", path.Dir(newName))
		}
		_, err = sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "UPDATE files SET file_path = {newName}, mod_time = {modTime}{reparent} WHERE file_path = {oldName}",
			Values: []any{
				sq.StringParam("newName", newName),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.Param("reparent", reparent),
				sq.StringParam("oldName", oldName),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
		if result.isDir {
			// If the file is a directory, retrieve the descendants' total
			// size.
			totalSize, err = sq.FetchOne(fsys.ctx, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format:  "SELECT {*} FROM files WHERE file_path LIKE {pattern} ESCAPE '\\'",
				Values: []any{
					sq.StringParam("pattern", wildcardReplacer.Replace(oldName)+"/%"),
				},
			}, func(row *sq.Row) int64 {
				return row.Int64("sum(CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END)")
			})
			// Rename the directory prefix for all descendants.
			_, err = sq.Exec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
				Values: []any{
					sq.Param("filePath", sq.Expr("concat({}, substring(file_path, {}))", newName, utf8.RuneCountInString(oldName)+1)),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("pattern", wildcardReplacer.Replace(oldName)+"/%"),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		} else {
			totalSize = result.size
			if path.Ext(oldName) != path.Ext(newName) {
				return fmt.Errorf("file extension cannot be changed")
			}
		}
	default:
		return stacktrace.New(fmt.Errorf("unsupported dialect %q", fsys.Dialect))
	}
	err = tx.Commit()
	if err != nil {
		return stacktrace.New(err)
	}
	// If the files changed parents, need to update the size of all ancestor
	// directories accordingly.
	if path.Dir(oldName) != path.Dir(newName) {
		// Subtract the files' total size from all old ancestor directories.
		oldAncestors := make([]string, 0, strings.Count(oldName, "/"))
		for dir := path.Dir(oldName); dir != "."; dir = path.Dir(dir) {
			oldAncestors = append(oldAncestors, dir)
		}
		if len(oldAncestors) > 0 {
			_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
				Dialect: fsys.Dialect,
				Format: "UPDATE files" +
					" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
					" WHERE file_path IN ({oldAncestors})" +
					" AND is_dir",
				Values: []any{
					sq.Int64Param("delta", -totalSize),
					sq.Param("oldAncestors", oldAncestors),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		}
		// Add the files' total size to all new ancestor directories.
		newAncestors := make([]string, 0, strings.Count(newName, "/"))
		for dir := path.Dir(newName); dir != "."; dir = path.Dir(dir) {
			newAncestors = append(newAncestors, dir)
		}
		if len(newAncestors) > 0 {
			_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
				Dialect: fsys.Dialect,
				Format: "UPDATE files" +
					" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
					" WHERE file_path IN ({newAncestors})" +
					" AND is_dir",
				Values: []any{
					sq.Int64Param("delta", totalSize),
					sq.Param("newAncestors", newAncestors),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		}
	}
	return nil
}

// Copy implements the Copy FS operation for DatabaseFS.
func (fsys *DatabaseFS) Copy(srcName, destName string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(srcName) || strings.Contains(srcName, "\\") {
		return &fs.PathError{Op: "copy", Path: srcName, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(destName) || strings.Contains(destName, "\\") {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrInvalid}
	}
	var srcFileID ID
	var srcIsDir bool
	var destExists bool
	fileInfos, err := sq.FetchAll(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path IN ({srcName}, {destName})",
		Values: []any{
			sq.StringParam("srcName", srcName),
			sq.StringParam("destName", destName),
		},
	}, func(row *sq.Row) (fileInfo struct {
		FilePath string
		FileID   ID
		IsDir    bool
	}) {
		fileInfo.FilePath = row.String("file_path")
		fileInfo.FileID = row.UUID("file_id")
		fileInfo.IsDir = row.Bool("is_dir")
		return fileInfo
	})
	if err != nil {
		return stacktrace.New(err)
	}
	for _, fileInfo := range fileInfos {
		switch fileInfo.FilePath {
		case srcName:
			srcFileID = fileInfo.FileID
			srcIsDir = fileInfo.IsDir
		case destName:
			destExists = true
		}
	}
	// srcName must exist.
	if srcFileID.IsZero() {
		return fs.ErrNotExist
	}
	// destName must not exist.
	if destExists {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrExist}
	}
	if !srcIsDir {
		// If src file is not a directory, just copy the file and we are done.
		destFileID := NewID()
		size, err := sq.FetchOne(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {srcName}",
			Values: []any{
				sq.StringParam("srcName", srcName),
			},
		}, func(row *sq.Row) int64 {
			return row.Int64("size")
		})
		if err != nil {
			return stacktrace.New(err)
		}
		_, err = sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" {destFileID}" +
				", (SELECT file_id FROM files WHERE file_path = {destParent})" +
				", {destName}" +
				", {modTime}" +
				", {modTime}" +
				", is_dir" +
				", size" +
				", text" +
				", data" +
				" FROM files" +
				" WHERE file_path = {srcName}",
			Values: []any{
				sq.UUIDParam("destFileID", destFileID),
				sq.StringParam("destParent", path.Dir(destName)),
				sq.StringParam("destName", destName),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("srcName", srcName),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
		ext := path.Ext(srcName)
		fileType := AllowedFileTypes[strings.ToLower(ext)]
		if fileType.Has(AttributeObject) {
			err := fsys.ObjectStorage.Copy(fsys.ctx, srcFileID.String()+ext, destFileID.String()+ext)
			if err != nil {
				fsys.Logger.Error(stacktrace.New(err).Error())
			}
		}
		// Add the file size to the site's storage used.
		if fsys.UpdateStorageUsed != nil {
			var sitePrefix string
			head, _, _ := strings.Cut(srcName, "/")
			if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
				sitePrefix = head
			}
			err := fsys.UpdateStorageUsed(fsys.ctx, strings.TrimPrefix(sitePrefix, "@"), size)
			if err != nil {
				return stacktrace.New(err)
			}
		}
		// Add the file size to all dest ancestor directories.
		destAncestors := make([]string, 0, strings.Count(destName, "/"))
		for dir := path.Dir(destName); dir != "."; dir = path.Dir(dir) {
			destAncestors = append(destAncestors, dir)
		}
		if len(destAncestors) > 0 {
			_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
				Dialect: fsys.Dialect,
				Format: "UPDATE files" +
					" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
					" WHERE file_path IN ({destAncestors})" +
					" AND is_dir",
				Values: []any{
					sq.Int64Param("delta", size),
					sq.Param("destAncestors", destAncestors),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
		}
		return nil
	}
	// If we reach here, that means src file is a directory and we need to copy
	// files recursively.
	//
	// First, grab a list of all files we need to copy so that we can generate
	// new file IDs for their cloned versions.
	cursor, err := sq.FetchCursor(fsys.ctx, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {srcName} OR file_path LIKE {pattern} ESCAPE '\\' ORDER BY file_path",
		Values: []any{
			sq.StringParam("srcName", srcName),
			sq.StringParam("pattern", wildcardReplacer.Replace(srcName)+"/%"),
		},
	}, func(row *sq.Row) (srcFile struct {
		FileID   ID
		FilePath string
		IsDir    bool
		Size     int64
	}) {
		srcFile.FileID = row.UUID("file_id")
		srcFile.FilePath = row.String("file_path")
		srcFile.IsDir = row.Bool("is_dir")
		srcFile.Size = row.Int64("size")
		return srcFile
	})
	if err != nil {
		return err
	}
	defer cursor.Close()
	// Then, generate a JSON array containing new file IDs (for the new files
	// that will be copied). We will unmarshal this JSON payload on the
	// database-side using dialect-specific SQL and join it with the existing
	// files table in order to do a bulk cloning of files in one query.
	var wg sync.WaitGroup
	var totalSize int64
	var items [][4]string // [destFileID, destParentID, destParent, srcFilePath]
	fileIDs := make(map[string]ID)
	objectCtx, cancelObjectCtx := context.WithCancel(fsys.ctx)
	defer cancelObjectCtx()
	for cursor.Next() {
		srcFile, err := cursor.Result()
		if err != nil {
			return nil
		}
		destFileID := NewID()
		destFilePath := destName + strings.TrimPrefix(srcFile.FilePath, srcName)
		fileIDs[destFilePath] = destFileID
		var item [4]string
		item[0] = destFileID.String()
		destParent := path.Dir(destFilePath)
		// We are guaranteed to see a parent before its children, because we
		// `ORDER BY file_path`. So a file's parent ID will always be in the
		// map except for the very first file in the loop.
		if destParentID, ok := fileIDs[destParent]; ok {
			item[1] = destParentID.String()
		} else {
			item[2] = destParent
		}
		item[3] = srcFile.FilePath
		items = append(items, item)
		if !srcFile.IsDir {
			totalSize += srcFile.Size
			ext := path.Ext(srcFile.FilePath)
			fileType := AllowedFileTypes[strings.ToLower(ext)]
			if fileType.Has(AttributeObject) {
				wg.Add(1)
				go func() {
					defer func() {
						if v := recover(); v != nil {
							fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
						}
					}()
					defer wg.Done()
					err := fsys.ObjectStorage.Copy(objectCtx, hex.EncodeToString(srcFile.FileID[:])+ext, hex.EncodeToString(destFileID[:])+ext)
					if err != nil {
						fsys.Logger.Error(stacktrace.New(err).Error())
					}
				}()
			}
		}
	}
	err = cursor.Close()
	if err != nil {
		return err
	}
	var b strings.Builder
	err = json.NewEncoder(&b).Encode(items)
	if err != nil {
		return err
	}
	switch fsys.Dialect {
	case "sqlite":
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" unhex(items.value->>0, '-') AS dest_file_id" +
				", CASE WHEN items.value->>1 <> '' THEN unhex(items.value->>1, '-') ELSE (SELECT file_id FROM files WHERE file_path = items.value->>2) END AS dest_parent_id" +
				", {destName} || substring(src_files.file_path, {start}) AS dest_file_path" +
				", {modTime}" +
				", {modTime}" +
				", src_files.is_dir" +
				", src_files.size" +
				", src_files.text" +
				", src_files.data" +
				" FROM json_each({items}) AS items" +
				" JOIN files AS src_files ON src_files.file_path = items.value->>3",
			Values: []any{
				sq.StringParam("destName", destName),
				sq.IntParam("start", utf8.RuneCountInString(srcName)+1),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("items", b.String()),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	case "postgres":
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" CAST(items.value->>0 AS UUID) AS dest_file_id" +
				", CASE WHEN items.value->>1 <> '' THEN CAST(items.value->>1 AS UUID) ELSE (SELECT file_id FROM files WHERE file_path = items.value->>2) END AS dest_parent_id" +
				", {destName} || substring(src_files.file_path, {start}) AS dest_file_path" +
				", {modTime}" +
				", {modTime}" +
				", src_files.is_dir" +
				", src_files.size" +
				", src_files.text" +
				", src_files.data" +
				" FROM json_array_elements({items}) AS items" +
				" JOIN files AS src_files ON src_files.file_path = items.value->>3",
			Values: []any{
				sq.StringParam("destName", destName),
				sq.IntParam("start", utf8.RuneCountInString(srcName)+1),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("items", b.String()),
			},
		})
		if err != nil {
			return err
		}
	case "mysql":
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" uuid_to_bin(items.dest_file_id) AS dest_file_id" +
				", CASE WHEN items.dest_parent_id <> '' THEN uuid_to_bin(items.dest_parent_id) ELSE (SELECT file_id FROM files WHERE file_path = items.parent_path) END AS dest_parent_id" +
				", concat({destName}, substring(src_files.file_path, {start})) AS dest_file_path" +
				", {modTime}" +
				", {modTime}" +
				", src_files.is_dir" +
				", src_files.size" +
				", src_files.text" +
				", src_files.data" +
				" FROM json_table({items}, '$[*]' COLUMNS (" +
				"dest_file_id VARCHAR(36) PATH '$[0]'" +
				", dest_parent_id VARCHAR(36) PATH '$[1]'" +
				", dest_parent VARCHAR(500) PATH '$[2]'" +
				", src_file_path VARCHAR(500) PATH '$[3]'" +
				")) AS items" +
				" JOIN files AS src_files ON src_files.file_path = items.src_file_path",
			Values: []any{
				sq.StringParam("destName", destName),
				sq.IntParam("start", utf8.RuneCountInString(srcName)+1),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("items", b.String()),
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.Dialect)
	}
	// Add the files' total size from the site's storage used.
	if fsys.UpdateStorageUsed != nil {
		var sitePrefix string
		head, _, _ := strings.Cut(destName, "/")
		if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
			sitePrefix = head
		}
		err := fsys.UpdateStorageUsed(fsys.ctx, strings.TrimPrefix(sitePrefix, "@"), totalSize)
		if err != nil {
			return err
		}
	}
	// Add the files' total size to all dest ancestor directories.
	destAncestors := make([]string, 0, strings.Count(destName, "/"))
	for dir := path.Dir(destName); dir != "."; dir = path.Dir(dir) {
		destAncestors = append(destAncestors, dir)
	}
	if len(destAncestors) > 0 {
		_, err := sq.Exec(fsys.ctx, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "UPDATE files" +
				" SET size = CASE WHEN coalesce(size, 0) + {delta} >= 0 THEN coalesce(size, 0) + {delta} ELSE 0 END" +
				" WHERE file_path IN ({destAncestors})" +
				" AND is_dir",
			Values: []any{
				sq.Int64Param("delta", totalSize),
				sq.Param("destAncestors", destAncestors),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
	}
	wg.Wait()
	return nil
}

// IsKeyViolation returns true if the provided errorCode matches the
// dialect-specific code for representing a primary key/unique constraint
// violation.
func IsKeyViolation(dialect string, errorCode string) bool {
	switch dialect {
	case "sqlite":
		return errorCode == "1555" || errorCode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errorCode == "23505" // unique_violation
	case "mysql":
		return errorCode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errorCode == "2627"
	default:
		return false
	}
}

// IsForeignKeyViolation returns true if the provided errorCode matches the
// dialect-specific code for representing a foreign key constraint violation.
func IsForeignKeyViolation(dialect string, errorCode string) bool {
	switch dialect {
	case "sqlite":
		return errorCode == "787" //  SQLITE_CONSTRAINT_FOREIGNKEY
	case "postgres":
		return errorCode == "23503" // foreign_key_violation
	case "mysql":
		return errorCode == "1216" // ER_NO_REFERENCED_ROW
	case "sqlserver":
		return errorCode == "547"
	default:
		return false
	}
}

// IsFulltextIndexed reports whether a file is eligible for fulltext indexing
// by virtue of its position within the filesystem. For example, html files in
// the pages directory are fulltext indexed but not html files in the output
// directory because those are generated by notebrew itself (we don't want to
// index generated files, only user source files).
//
// If a file is not fulltext-indexed, it is stored in a DatabaseFS in gzipped
// form to save space and also to save CPU cycles as we don't have to gzip
// again when serving it later.
func IsFulltextIndexed(filePath string) bool {
	fileType, ok := AllowedFileTypes[strings.ToLower(path.Ext(filePath))]
	if !ok {
		return false
	}
	head, tail, _ := strings.Cut(filePath, "/")
	if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
		head, tail, _ = strings.Cut(tail, "/")
	}
	switch head {
	case "notes":
		return fileType.Has(AttributeEditable)
	case "pages":
		return fileType.Ext == ".html"
	case "posts":
		name := path.Base(filePath)
		return fileType.Ext == ".md" || name == "post.html" || name == "postlist.html"
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		switch next {
		case "posts":
			return false
		case "themes":
			return fileType.Has(AttributeEditable)
		default:
			return fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
		}
	}
	return false
}
