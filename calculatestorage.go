package notebrew

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) calculatestorage(w http.ResponseWriter, r *http.Request, user User) {
	if nbrew.DB == nil {
		nbrew.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType == "multipart/form-data" {
		err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
		if err != nil {
			nbrew.BadRequest(w, r, err)
			return
		}
	} else {
		err := r.ParseForm()
		if err != nil {
			nbrew.BadRequest(w, r, err)
			return
		}
	}
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	startedAt := time.Now()
	group, groupctx := errgroup.WithContext(r.Context())
	siteNames := r.Form["siteName"]
	for _, siteName := range siteNames {
		siteName := siteName
		exists, err := sq.FetchExists(groupctx, nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "SELECT 1" +
				" FROM site_owner" +
				" WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})" +
				" AND user_id = (SELECT user_id FROM users WHERE username = {username})",
			Values: []any{
				sq.StringParam("siteName", siteName),
				sq.StringParam("username", user.Username),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if !exists {
			continue
		}
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			var root string
			if siteName == "" {
				root = "."
			} else if strings.Contains(siteName, ".") {
				root = siteName
			} else {
				root = "@" + siteName
			}
			storageUsed, err := calculateStorageUsed(r.Context(), nbrew.FS, root)
			if err != nil {
				return stacktrace.New(err)
			}
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "UPDATE site SET storage_used = {storageUsed} WHERE site_name = {siteName}",
				Values: []any{
					sq.Int64Param("storageUsed", storageUsed),
					sq.StringParam("siteName", siteName),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		})
		if isDatabaseFS {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var siteFilter sq.Expression
				if siteName == "" {
					siteFilter = sq.Expr("(" +
						"file_path LIKE 'notes/%' ESCAPE '\\'" +
						" OR file_path LIKE 'pages/%' ESCAPE '\\'" +
						" OR file_path LIKE 'posts/%' ESCAPE '\\'" +
						" OR file_path LIKE 'output/%' ESCAPE '\\'" +
						")",
					)
				} else {
					var sitePrefix string
					if strings.Contains(siteName, ".") {
						sitePrefix = siteName
					} else {
						sitePrefix = "@" + siteName
					}
					siteFilter = sq.Expr("file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(sitePrefix)+"/%")
				}
				cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format:  "SELECT {*} FROM files WHERE {siteFilter} AND NOT is_dir",
					Values: []any{
						sq.Param("siteFilter", siteFilter),
					},
				}, func(row *sq.Row) (result struct {
					FilePath string
					Size     int64
				}) {
					result.FilePath = row.String("file_path")
					result.Size = row.Int64("size")
					return result
				})
				if err != nil {
					return stacktrace.New(err)
				}
				defer cursor.Close()
				dirSizes := make(map[string]*int64)
				for cursor.Next() {
					result, err := cursor.Result()
					if err != nil {
						return stacktrace.New(err)
					}
					for dir := path.Dir(result.FilePath); dir != "."; dir = path.Dir(dir) {
						size := dirSizes[dir]
						if size == nil {
							size = new(int64)
							dirSizes[dir] = size
						}
						*size += result.Size
					}
				}
				err = cursor.Close()
				if err != nil {
					return stacktrace.New(err)
				}
				var db sq.DB
				if databaseFS.Dialect == "sqlite" {
					db = databaseFS.DB
				} else {
					var conn *sql.Conn
					conn, err = databaseFS.DB.Conn(groupctx)
					if err != nil {
						return stacktrace.New(err)
					}
					defer conn.Close()
					db = conn
				}
				preparedExec, err := sq.PrepareExec(groupctx, db, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "UPDATE files SET size = {size} WHERE file_path = {dir} AND is_dir",
					Values: []any{
						sq.Int64Param("size", 0),
						sq.StringParam("dir", ""),
					},
				})
				defer preparedExec.Close()
				subgroup, subctx := errgroup.WithContext(groupctx)
				for dir, size := range dirSizes {
					dir, size := dir, size
					subgroup.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						_, err = preparedExec.Exec(subctx, sq.Int64Param("size", *size), sq.StringParam("dir", dir))
						if err != nil {
							return stacktrace.New(err)
						}
						return nil
					})
				}
				err = subgroup.Wait()
				if err != nil {
					return err
				}
				return nil
			})
		}
	}
	err := group.Wait()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	timeTaken := time.Since(startedAt)
	err = nbrew.SetFlashSession(w, r, map[string]any{
		"postRedirectGet": map[string]any{
			"from":      "calculatestorage",
			"timeTaken": timeTaken.String(),
		},
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/files/", http.StatusFound)
		return
	}
	http.Redirect(w, r, referer, http.StatusFound)
}

func calculateStorageUsed(ctx context.Context, fsys FS, root string) (int64, error) {
	var sitePrefix string
	root = strings.Trim(root, "/")
	if root != "." {
		head, _, _ := strings.Cut(root, "/")
		if strings.HasPrefix(head, "@") || strings.Contains(root, ".") {
			sitePrefix = head
		}
	}
	databaseFS, ok := &DatabaseFS{}, false
	switch v := fsys.(type) {
	case *DatabaseFS:
		databaseFS, ok = v, true
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		var filter sq.Expression
		if root == "." || sitePrefix == root {
			filter = sq.Expr("("+
				"files.file_path LIKE {notesPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {pagesPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {postsPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {outputPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {importsPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {exportsPrefix} ESCAPE '\\'"+
				" OR files.file_path = {siteJSON}"+
				")",
				sq.StringParam("notesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "notes"))+"/%"),
				sq.StringParam("pagesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "pages"))+"/%"),
				sq.StringParam("postsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "posts"))+"/%"),
				sq.StringParam("outputPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output"))+"/%"),
				sq.StringParam("importsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "imports"))+"/%"),
				sq.StringParam("exportsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "exports"))+"/%"),
				sq.StringParam("siteJSON", path.Join(sitePrefix, "site.json")),
			)
		} else {
			filter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(root)+"/%")
		}
		storageUsed, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE {filter}",
			Values: []any{
				sq.Param("filter", filter),
			},
		}, func(row *sq.Row) int64 {
			return row.Int64("sum(CASE WHEN is_dir OR size IS NULL THEN 0 ELSE size END)")
		})
		if err != nil {
			return 0, stacktrace.New(err)
		}
		return storageUsed, nil
	}
	var storageUsed atomic.Int64
	walkDirFunc := func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return stacktrace.New(err)
		}
		if dirEntry.IsDir() {
			return nil
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return stacktrace.New(err)
		}
		storageUsed.Add(fileInfo.Size())
		return nil
	}
	if root == "." || sitePrefix == root {
		group, groupctx := errgroup.WithContext(ctx)
		for _, root := range []string{
			path.Join(sitePrefix, "notes"),
			path.Join(sitePrefix, "pages"),
			path.Join(sitePrefix, "posts"),
			path.Join(sitePrefix, "output"),
			path.Join(sitePrefix, "imports"),
			path.Join(sitePrefix, "exports"),
			path.Join(sitePrefix, "site.json"),
		} {
			root := root
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				err = fs.WalkDir(fsys.WithContext(groupctx), root, walkDirFunc)
				if err != nil {
					return err
				}
				return nil
			})
		}
		err := group.Wait()
		if err != nil {
			return 0, err
		}
	} else {
		err := fs.WalkDir(fsys.WithContext(ctx), root, walkDirFunc)
		if err != nil {
			return 0, err
		}
	}
	return storageUsed.Load(), nil
}
