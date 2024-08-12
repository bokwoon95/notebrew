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

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	// OpenWriter opens an io.WriteCloser that represents an instance of a
	// file. The parent directory must exist. If the file doesn't exist, it
	// should be created. If the file exists, its should be truncated.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)

	ReadDir(name string) ([]fs.DirEntry, error)

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error

	MkdirAll(name string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	RemoveAll(name string) error

	// Rename renames (moves) oldName to newName. newName must not exist.
	Rename(oldName, newName string) error

	Copy(srcName, destName string) error
}

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

type FileType struct {
	Ext         string
	ContentType string
	Limit       int64
	Attribute   Attribute
}

func (fileType FileType) Has(attribute Attribute) bool {
	return fileType.Attribute&attribute != 0
}

var AllowedFileTypes = map[string]FileType{
	".html": {
		Ext:         ".html",
		ContentType: "text/html; charset=utf-8",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".css": {
		Ext:         ".css",
		ContentType: "text/css; charset=utf-8",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".js": {
		Ext:         ".js",
		ContentType: "text/javascript; charset=utf-8",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".md": {
		Ext:         ".md",
		ContentType: "text/markdown; charset=utf-8",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".txt": {
		Ext:         ".txt",
		ContentType: "text/plain; charset=utf-8",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeEditable,
	},
	".jpeg": {
		Ext:         ".jpeg",
		ContentType: "image/jpeg",
		Limit:       10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".jpg": {
		Ext:         ".jpg",
		ContentType: "image/jpeg",
		Limit:       10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".png": {
		Ext:         ".png",
		ContentType: "image/png",
		Limit:       10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".webp": {
		Ext:         ".webp",
		ContentType: "image/webp",
		Limit:       10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".gif": {
		Ext:         ".gif",
		ContentType: "image/gif",
		Limit:       10 << 20, /* 10 MB */
		Attribute:   AttributeObject | AttributeImg,
	},
	".svg": {
		Ext:         ".svg",
		ContentType: "image/svg+xml",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable | AttributeImg,
	},
	".eot": {
		Ext:         ".eot",
		ContentType: "font/eot",
		Limit:       2 << 20, /* 2 MB */
		Attribute:   AttributeGzippable | AttributeFont,
	},
	".otf": {
		Ext:         ".otf",
		ContentType: "font/otf",
		Limit:       2 << 20, /* 2 MB */
		Attribute:   AttributeGzippable | AttributeFont,
	},
	".ttf": {
		Ext:         ".ttf",
		ContentType: "font/ttf",
		Limit:       2 << 20, /* 2 MB */
		Attribute:   AttributeGzippable | AttributeFont,
	},
	".woff": {
		Ext:         ".woff",
		ContentType: "font/woff",
		Limit:       2 << 20, /* 2 MB */
		Attribute:   AttributeFont,
	},
	".woff2": {
		Ext:         ".woff2",
		ContentType: "font/woff2",
		Limit:       2 << 20, /* 2 MB */
		Attribute:   AttributeFont,
	},
	".atom": {
		Ext:         ".atom",
		ContentType: "application/atom+xml; charset=utf-8",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable,
	},
	".json": {
		Ext:         ".json",
		ContentType: "application/json",
		Limit:       1 << 20, /* 1 MB */
		Attribute:   AttributeGzippable,
	},
	".tgz": {
		Ext:         ".tgz",
		ContentType: "application/octet-stream",
		Limit:       -1, /* no limit */
		Attribute:   AttributeObject | AttributeAttachment,
	},
}

var (
	editableExts []string // do not modify! only read
	imgExts      []string // do not modify! only read
	fontExts     []string // do not modify! only read
	populateExts = sync.OnceFunc(func() {
		for _, fileType := range AllowedFileTypes {
			if fileType.Has(AttributeEditable) {
				editableExts = append(editableExts, fileType.Ext)
			}
			if fileType.Has(AttributeImg) {
				imgExts = append(imgExts, fileType.Ext)
			}
			if fileType.Has(AttributeFont) {
				fontExts = append(fontExts, fileType.Ext)
			}
		}
		slices.Sort(editableExts)
		slices.Sort(imgExts)
		slices.Sort(fontExts)
	})
)
