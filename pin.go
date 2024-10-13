package notebrew

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) pin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		Error     string `json:"error"`
		Parent    string `json:"parent"`
		NumPinned int    `json:"numPinned"`
	}
	databaseFS, ok := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if !ok {
		nbrew.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
		return
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
			}
			return
		}
		if response.Error != "" {
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
			return
		}
		err := nbrew.SetFlashSession(w, r, map[string]any{
			"postRedirectGet": map[string]any{
				"from":      "pin",
				"numPinned": response.NumPinned,
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	}
	response := Response{
		Parent: path.Clean(strings.Trim(r.Form.Get("parent"), "/")),
	}
	head, _, _ := strings.Cut(response.Parent, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" && head != "imports" && head != "exports" {
		response.Error = "InvalidParent"
		writeResponse(w, r, response)
		return
	}
	parentID, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {parent} AND is_dir",
		Values: []any{
			sq.StringParam("parent", path.Join(sitePrefix, response.Parent)),
		},
	}, func(row *sq.Row) ID {
		return row.UUID("file_id")
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	names := r.Form["name"]
	if len(names) == 0 {
		http.Redirect(w, r, referer, http.StatusFound)
		return
	}
	slices.Sort(names)
	names = slices.Compact(names)
	numPinned := atomic.Int64{}
	tx, err := databaseFS.DB.BeginTx(r.Context(), nil)
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	defer tx.Rollback()
	var preparedExec *sq.PreparedExec
	defer func() {
		if preparedExec == nil {
			return
		}
		preparedExec.Close()
	}()
	switch databaseFS.Dialect {
	case "sqlite", "postgres":
		preparedExec, err = sq.PrepareExec(r.Context(), tx, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "INSERT INTO pinned_file (parent_id, file_id)" +
				" SELECT {parentID}, file_id FROM files WHERE file_path = {filePath}" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.UUIDParam("parentID", parentID),
				sq.Param("filePath", nil),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
	case "mysql":
		preparedExec, err = sq.PrepareExec(r.Context(), tx, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "INSERT INTO pinned_file (parent_id, file_id, creation_time)" +
				" SELECT {parentID}, file_id FROM files WHERE file_path = {filePath}" +
				" ON DUPLICATE KEY UPDATE parent_id = parent_id",
			Values: []any{
				sq.UUIDParam("parentID", parentID),
				sq.Param("filePath", nil),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
	default:
		panic(fmt.Sprintf("unsupported dialect %q", databaseFS.Dialect))
	}
	group, groupctx := errgroup.WithContext(r.Context())
	for _, name := range names {
		name := name
		if strings.Contains(name, "/") {
			continue
		}
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			result, err := preparedExec.Exec(groupctx, sq.StringParam("filePath", path.Join(sitePrefix, response.Parent, name)))
			if err != nil {
				return stacktrace.New(err)
			}
			if result.RowsAffected > 0 {
				numPinned.Add(1)
			}
			return nil
		})
	}
	err = group.Wait()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	err = tx.Commit()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	response.NumPinned = int(numPinned.Load())
	writeResponse(w, r, response)
}
