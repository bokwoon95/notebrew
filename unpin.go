package notebrew

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) unpin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		Size         int64     `json:"size"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Response struct {
		ContentBaseURL        string `json:"contentBaseURL"`
		CDNDomain             string `json:"cdnDomain"`
		IsDatabaseFS          bool   `json:"isDatabaseFS"`
		SitePrefix            string `json:"sitePrefix"`
		UserID                ID     `json:"userID"`
		Username              string `json:"username"`
		TimezoneOffsetSeconds int    `json:"timezoneOffsetSeconds"`
		DisableReason         string `json:"disableReason"`
		Parent                string `json:"parent"`
		Files                 []File `json:"files"`
		Error                 string `json:"error"`
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

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusOK)
					return
				}
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			referer := nbrew.GetReferer(r)
			funcMap := map[string]any{
				"join":                  path.Join,
				"base":                  path.Base,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"formatTime": func(t time.Time, layout string, offset int) string {
					return t.In(time.FixedZone("", offset)).Format(layout)
				},
				"getFileType": func(name string) FileType {
					return AllowedFileTypes[strings.ToLower(path.Ext(name))]
				},
			}
			tmpl, err := template.New("unpin.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/unpin.html")
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.CDNDomain = nbrew.CDNDomain
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			response.IsDatabaseFS = v.As(&DatabaseFS{})
		}
		response.UserID = user.UserID
		response.Username = user.Username
		response.TimezoneOffsetSeconds = user.TimezoneOffsetSeconds
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		if head != "notes" && head != "pages" && head != "posts" && head != "output" && head != "imports" && head != "exports" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.Parent))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if !fileInfo.IsDir() {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		seen := make(map[string]bool)
		group, groupctx := errgroup.WithContext(r.Context())
		names := r.Form["name"]
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, filepath.ToSlash(name)
			if !strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return stacktrace.New(err)
				}
				file := File{
					Name:    name,
					IsDir:   fileInfo.IsDir(),
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				}
				if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
					file.FileID = databaseFileInfo.FileID
					file.CreationTime = databaseFileInfo.CreationTime
				} else {
					var absolutePath string
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						var directoryFS *DirectoryFS
						if v.As(&directoryFS) {
							absolutePath = path.Join(directoryFS.RootDir, sitePrefix, response.Parent, name)
						}
					}
					file.CreationTime = CreationTime(absolutePath, fileInfo)
				}
				response.Files[i] = file
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		writeResponse(w, r, response)
	case "POST":
		if user.DisableReason != "" {
			nbrew.AccountDisabled(w, r, user.DisableReason)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		err := r.ParseForm()
		if err != nil {
			nbrew.BadRequest(w, r, err)
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
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "unpin")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":        "unpin",
					"numUnpinned": len(response.Files),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			head, tail, _ := strings.Cut(response.Parent, "/")
			if head != "output" {
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
				return
			}
			next, _, _ := strings.Cut(tail, "/")
			switch next {
			case "themes":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
				return
			case "posts":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, tail+".md"), http.StatusFound)
				return
			case "":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "pages/index.html"), http.StatusFound)
				return
			default:
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "pages", tail+".html"), http.StatusFound)
				return
			}
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
			writeResponse(w, r, response)
			return
		}
		slices.Sort(names)
		names = slices.Compact(names)
		tx, err := databaseFS.DB.BeginTx(r.Context(), nil)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer tx.Rollback()
		preparedExec, err := sq.PrepareExec(r.Context(), tx, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "DELETE FROM pinned_file" +
				" WHERE parent_id = {parentID}" +
				" AND file_id = (SELECT file_id FROM files WHERE file_path = {filePath})",
			Values: []any{
				sq.UUIDParam("parentID", parentID),
				sq.StringParam("filePath", ""),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer preparedExec.Close()
		group, groupctx := errgroup.WithContext(r.Context())
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, name
			if !strings.Contains(name, "/") {
				continue
			}
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				result, err := preparedExec.Exec(groupctx, sq.StringParam("filePath", path.Join(sitePrefix, name)))
				if err != nil {
					return stacktrace.New(err)
				}
				if result.RowsAffected > 0 {
					response.Files[i] = File{
						Name: name,
					}
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
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
