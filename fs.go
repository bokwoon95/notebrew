package notebrew

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"slices"
	"sync"
)

// If a buffer's capacity exceeds this value, don't put it back in the pool
// because it's too expensive to keep it around in memory.
//
// From https://victoriametrics.com/blog/tsdb-performance-techniques-sync-pool/
//
// "The maximum capacity of a cached pool is limited to 2^18 bytes as we’ve
// found that the RAM cost of storing buffers larger than this limit is not
// worth the savings of not recreating those buffers."
const maxPoolableBufferCapacity = 1 << 18

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

// FS represents a writeable filesystem.
type FS interface {
	// WithContext returns a new FS with the given context which applies to all
	// subsequent operations carried out by the filesystem.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	// OpenWriter opens an io.WriteCloser that represents a writeable instance
	// of a file. The parent directory must exist. If the file doesn't exist,
	// it should be created. If the file exists, its should be truncated. Write
	// operations should ideally be atomic i.e. if two writers are writing to
	// the same file, last writer wins.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)

	// ReadDir reads the named directory and returns a list of directory
	// entries sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error)

	// Mkdir creates a new directory with the specified name. The directory
	// should not already exist.
	Mkdir(name string, perm fs.FileMode) error

	// MkdirAll creates a directory with the given name, along with any
	// necessary parents, and returns nil, or else returns an error.
	MkdirAll(name string, perm fs.FileMode) error

	// Remove removes the named file or directory. The file should exist. If
	// the file is a directory, the directory should be empty.
	Remove(name string) error

	// RemoveAll removes name and any children it contains. It removes
	// everything it can but returns the first error it encounters. If the path
	// does not exist, RemoveAll returns nil (no error).
	RemoveAll(name string) error

	// Rename renames (moves) oldName to newName. newName must not exist.
	Rename(oldName, newName string) error

	// Copy copies the srcName to destName. destName must not exist.
	Copy(srcName, destName string) error
}

// Attribute represents the various attributes that a file type have e.g.
// whether it is gzippable, whether it's an object, etc.
type Attribute int

const (
	AttributeGzippable  Attribute = 1 << 0 // Should be gzipped when sent in the response body.
	AttributeObject     Attribute = 1 << 1 // Should be stored in ObjectStorage (instead of the database).
	AttributeAttachment Attribute = 1 << 2 // Should be downloaded with Content-Disposition: attachment.
	AttributeEditable   Attribute = 1 << 3 // Can be edited by the user.
	AttributeFont       Attribute = 1 << 4 // Can be used as a @font-face src.
	AttributeImg        Attribute = 1 << 5 // Can be displayed with an <img> tag.
	AttributeVideo      Attribute = 1 << 6 // Can be displayed with a <video> tag.
)

// FileType represents a file type.
type FileType struct {
	Ext         string    // File extension.
	ContentType string    // Content-Type that file should be served with.
	SizeLimit   int64     // Size limit for the file type.
	Attribute   Attribute // File type attributes.
}

// Has reports whether a particular file type contains the attribute.
func (fileType FileType) Has(attribute Attribute) bool {
	return fileType.Attribute&attribute != 0
}

// IsImg is shorthand for Has(AttributeImg). Used in templates, which do not
// have access to the Attribute* constants.
func (fileType FileType) IsImg() bool {
	return fileType.Has(AttributeImg)
}

// IsObject is shorthand for Has(AttributeObject). Used in templates, which do
// not have access to the Attribute* constants.
func (fileType FileType) IsObject() bool {
	return fileType.Has(AttributeObject)
}

// AllowedFileTypes is a list of file types allowed by notebrew.
//
// It is exported so that people using notebrew as a library may add their own
// file types to it, although no effort has been made to test whether such
// additions would work seamlessly with the rest of the library.
var AllowedFileTypes = map[string]FileType{
	".html": {
		Ext:         ".html",
		ContentType: "text/html; charset=utf-8",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".css": {
		Ext:         ".css",
		ContentType: "text/css; charset=utf-8",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".js": {
		Ext:         ".js",
		ContentType: "text/javascript; charset=utf-8",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".md": {
		Ext:         ".md",
		ContentType: "text/markdown; charset=utf-8",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".txt": {
		Ext:         ".txt",
		ContentType: "text/plain; charset=utf-8",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".jpeg": {
		Ext:         ".jpeg",
		ContentType: "image/jpeg",
		SizeLimit:   10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".jpg": {
		Ext:         ".jpg",
		ContentType: "image/jpeg",
		SizeLimit:   10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".png": {
		Ext:         ".png",
		ContentType: "image/png",
		SizeLimit:   10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".webp": {
		Ext:         ".webp",
		ContentType: "image/webp",
		SizeLimit:   10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".gif": {
		Ext:         ".gif",
		ContentType: "image/gif",
		SizeLimit:   10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".svg": {
		Ext:         ".svg",
		ContentType: "image/svg+xml",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeImg,
	},
	".mp4": {
		Ext:         ".mp4",
		ContentType: "video/mp4",
		SizeLimit:   25 << 20, /* 25 MB */
		Attribute:   AttributeObject | AttributeVideo,
	},
	".webm": {
		Ext:         ".mp4",
		ContentType: "video/webm",
		SizeLimit:   25 << 20, /* 25 MB */
		Attribute:   AttributeObject | AttributeVideo,
	},
	".eot": {
		Ext:         ".eot",
		ContentType: "font/eot",
		SizeLimit:   2 << 20, /* 2 MB */
		Attribute:   AttributeGzippable | AttributeFont,
	},
	".otf": {
		Ext:         ".otf",
		ContentType: "font/otf",
		SizeLimit:   2 << 20, /* 2 MB */
		Attribute:   AttributeGzippable | AttributeFont,
	},
	".ttf": {
		Ext:         ".ttf",
		ContentType: "font/ttf",
		SizeLimit:   2 << 20, /* 2 MB */
		Attribute:   AttributeGzippable | AttributeFont,
	},
	".woff": {
		Ext:         ".woff",
		ContentType: "font/woff",
		SizeLimit:   2 << 20, /* 2 MB */
		Attribute:   AttributeFont,
	},
	".woff2": {
		Ext:         ".woff2",
		ContentType: "font/woff2",
		SizeLimit:   2 << 20, /* 2 MB */
		Attribute:   AttributeFont,
	},
	".atom": {
		Ext:         ".atom",
		ContentType: "application/atom+xml; charset=utf-8",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable,
	},
	".json": {
		Ext:         ".json",
		ContentType: "application/json",
		SizeLimit:   1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable,
	},
	".tgz": {
		Ext:         ".tgz",
		ContentType: "application/octet-stream",
		SizeLimit:   -1, /* no limit */
		Attribute:   AttributeObject | AttributeAttachment,
	},
}

var (
	editableExts []string // do not modify! only read
	imgExts      []string // do not modify! only read
	videoExts    []string // do not modify! only read
	fontExts     []string // do not modify! only read
	objectExts   []string // do not modify! only read
	populateExts = sync.OnceFunc(func() {
		for _, fileType := range AllowedFileTypes {
			if fileType.Has(AttributeEditable) {
				editableExts = append(editableExts, fileType.Ext)
			}
			if fileType.Has(AttributeImg) {
				imgExts = append(imgExts, fileType.Ext)
			}
			if fileType.Has(AttributeVideo) {
				videoExts = append(videoExts, fileType.Ext)
			}
			if fileType.Has(AttributeFont) {
				fontExts = append(fontExts, fileType.Ext)
			}
			if fileType.Has(AttributeObject) {
				objectExts = append(objectExts, fileType.Ext)
			}
		}
		slices.Sort(editableExts)
		slices.Sort(imgExts)
		slices.Sort(videoExts)
		slices.Sort(fontExts)
		slices.Sort(objectExts)
	})
)
