package notebrew

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) file(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, file fs.File, fileInfo fs.FileInfo) {
	type Asset struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		IsObject     bool      `json:"isObject"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
		Content      string    `json:"content"`
		AltText      string    `json:"altText"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		CDNDomain         string            `json:"cdnDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		FileID            ID                `json:"fileID"`
		FilePath          string            `json:"filePath"`
		IsDir             bool              `json:"isDir"`
		ModTime           time.Time         `json:"modTime"`
		CreationTime      time.Time         `json:"creationTime"`
		Size              int64             `json:"size"`
		Content           string            `json:"content"`
		URL               template.URL      `json:"url"`
		BelongsTo         string            `json:"belongsTo"`
		AssetDir          string            `json:"assetDir"`
		UploadableExts    []string          `json:"uploadableExts"`
		PinnedAssets      []Asset           `json:"pinnedAssets"`
		Assets            []Asset           `json:"assets"`
		UploadCount       int64             `json:"uploadCount"`
		UploadSize        int64             `json:"uploadSize"`
		FilesExist        []string          `json:"filesExist"`
		FilesTooBig       []string          `json:"filesTooBig"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}

	fileType, ok := AllowedFileTypes[path.Ext(filePath)]
	if !ok {
		nbrew.NotFound(w, r)
		return
	}

	// Figure out if the file is a user-editable file.
	var isEditable bool
	head, tail, _ := strings.Cut(filePath, "/")
	switch head {
	case "":
		nbrew.NotFound(w, r)
		return
	case "notes":
		isEditable = fileType.Has(AttributeEditable)
	case "pages":
		isEditable = fileType.Ext == ".html"
	case "posts":
		parent := path.Dir(tail)
		name := path.Base(tail)
		isEditable = fileType.Ext == ".md" || ((name == "post.html" || name == "postlist.html") && !strings.Contains(parent, "/"))
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		switch next {
		case "":
			isEditable = fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
		case "posts":
			isEditable = false
		case "themes":
			isEditable = fileType.Has(AttributeEditable)
		default:
			isEditable = fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
		}
		if fileType.Ext == ".html" && !isEditable {
			fileType.ContentType = "text/plain; charset=utf-8"
		}
	default:
		nbrew.NotFound(w, r)
		return
	}

	switch r.Method {
	case "GET", "HEAD":
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.FileID = databaseFileInfo.FileID
			response.CreationTime = databaseFileInfo.CreationTime
		} else {
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
				}
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}
		response.FilePath = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		response.Size = fileInfo.Size()
		response.CDNDomain = nbrew.CDNDomain
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			response.IsDatabaseFS = v.As(&DatabaseFS{})
		}

		if r.Form.Has("raw") {
			fileType, ok := AllowedFileTypes[path.Ext(filePath)]
			if !ok {
				nbrew.NotFound(w, r)
				return
			}
			if fileType.Ext == ".html" {
				fileType.ContentType = "text/plain; charset=utf-8"
			}
			ServeFile(w, r, path.Base(filePath), fileInfo.Size(), fileType, file, "no-cache")
			return
		}
		if isEditable {
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.Content = b.String()
		}

		switch head {
		case "pages":
			if tail == "index.html" {
				response.URL = template.URL(response.ContentBaseURL)
				response.AssetDir = "output"
			} else {
				response.URL = template.URL(response.ContentBaseURL + "/" + strings.TrimSuffix(tail, ".html") + "/")
				response.AssetDir = path.Join("output", strings.TrimSuffix(tail, ".html"))
			}
			response.UploadableExts = make([]string, 0, len(imgExts)+3)
			if !user.UserFlags["NoUploadImage"] {
				response.UploadableExts = append(response.UploadableExts, imgExts...)
			}
			response.UploadableExts = append(response.UploadableExts, ".css", ".js", ".md")
			assetExts := make([]string, 0, len(imgExts)+3)
			assetExts = append(assetExts, imgExts...)
			assetExts = append(assetExts, ".css", ".js", ".md")
			extFilter := sq.Expr("1 <> 1")
			if len(assetExts) > 0 {
				var b strings.Builder
				args := make([]any, 0, len(assetExts))
				b.WriteString("(")
				for i, ext := range assetExts {
					if i > 0 {
						b.WriteString(" OR ")
					}
					b.WriteString("files.file_path LIKE {} ESCAPE '\\'")
					args = append(args, "%"+wildcardReplacer.Replace(ext))
				}
				b.WriteString(")")
				extFilter = sq.Expr(b.String(), args...)
			}
			databaseFS, ok := &DatabaseFS{}, false
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				ok = v.As(&databaseFS)
			}
			if ok {
				group, groupctx := errgroup.WithContext(r.Context())
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					pinnedAssets, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM pinned_file" +
							" JOIN files ON files.file_id = pinned_file.file_id" +
							" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT files.is_dir" +
							" AND {extFilter}" +
							" ORDER BY files.file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
							sq.Param("extFilter", extFilter),
						},
					}, func(row *sq.Row) Asset {
						filePath := row.String("files.file_path")
						return Asset{
							FileID:       row.UUID("files.file_id"),
							Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
							Name:         path.Base(filePath),
							Size:         row.Int64("files.size"),
							ModTime:      row.Time("files.mod_time"),
							CreationTime: row.Time("files.creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil {
						return stacktrace.New(err)
					}
					response.PinnedAssets = pinnedAssets
					for i := range response.PinnedAssets {
						asset := &response.PinnedAssets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					assets, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM files" +
							" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT is_dir" +
							" AND {extFilter}" +
							" ORDER BY file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
							sq.Param("extFilter", extFilter),
						},
					}, func(row *sq.Row) Asset {
						return Asset{
							FileID:       row.UUID("file_id"),
							Parent:       response.AssetDir,
							Name:         path.Base(row.String("file_path")),
							Size:         row.Int64("size"),
							ModTime:      row.Time("mod_time"),
							CreationTime: row.Time("creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return stacktrace.New(err)
					}
					response.Assets = assets
					for i := range response.Assets {
						asset := &response.Assets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				err := group.Wait()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					fileType := AllowedFileTypes[path.Ext(name)]
					if fileType.Has(AttributeImg) || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" {
						fileInfo, err := dirEntry.Info()
						if err != nil {
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, response.AssetDir, name)
							}
						}
						response.Assets = append(response.Assets, Asset{
							Parent:       response.AssetDir,
							Name:         name,
							Size:         fileInfo.Size(),
							ModTime:      fileInfo.ModTime(),
							CreationTime: CreationTime(absolutePath, fileInfo),
						})
					}
				}
			}
		case "posts":
			if strings.HasSuffix(filePath, "/postlist.html") {
				response.URL = template.URL(response.ContentBaseURL + "/" + strings.TrimSuffix(filePath, "/postlist.html") + "/")
			} else if strings.HasSuffix(filePath, ".md") {
				response.URL = template.URL(response.ContentBaseURL + "/" + strings.TrimSuffix(filePath, ".md") + "/")
			}
			response.AssetDir = path.Join("output", strings.TrimSuffix(filePath, ".md"))
			if !user.UserFlags["NoUploadImage"] {
				response.UploadableExts = imgExts
			}
			extFilter := sq.Expr("1 <> 1")
			if len(imgExts) > 0 {
				var b strings.Builder
				args := make([]any, 0, len(imgExts))
				b.WriteString("(")
				for i, ext := range imgExts {
					if i > 0 {
						b.WriteString(" OR ")
					}
					b.WriteString("files.file_path LIKE {} ESCAPE '\\'")
					args = append(args, "%"+wildcardReplacer.Replace(ext))
				}
				b.WriteString(")")
				extFilter = sq.Expr(b.String(), args...)
			}
			databaseFS, ok := &DatabaseFS{}, false
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				ok = v.As(&databaseFS)
			}
			if ok {
				group, groupctx := errgroup.WithContext(r.Context())
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					pinnedAssets, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM pinned_file" +
							" JOIN files ON files.file_id = pinned_file.file_id" +
							" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT files.is_dir" +
							" AND {extFilter}" +
							" ORDER BY files.file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
							sq.Param("extFilter", extFilter),
						},
					}, func(row *sq.Row) Asset {
						filePath := row.String("files.file_path")
						return Asset{
							FileID:       row.UUID("files.file_id"),
							Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
							Name:         path.Base(filePath),
							Size:         row.Int64("files.size"),
							ModTime:      row.Time("files.mod_time"),
							CreationTime: row.Time("files.creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil {
						return stacktrace.New(err)
					}
					response.PinnedAssets = pinnedAssets
					for i := range response.PinnedAssets {
						asset := &response.PinnedAssets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					assets, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM files" +
							" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT is_dir" +
							" AND {extFilter}" +
							" ORDER BY file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
							sq.Param("extFilter", extFilter),
						},
					}, func(row *sq.Row) Asset {
						return Asset{
							FileID:       row.UUID("file_id"),
							Parent:       response.AssetDir,
							Name:         path.Base(row.String("file_path")),
							Size:         row.Int64("size"),
							ModTime:      row.Time("mod_time"),
							CreationTime: row.Time("creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return stacktrace.New(err)
					}
					response.Assets = assets
					for i := range response.Assets {
						asset := &response.Assets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				err := group.Wait()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					fileType := AllowedFileTypes[path.Ext(name)]
					if fileType.Has(AttributeImg) {
						fileInfo, err := dirEntry.Info()
						if err != nil {
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, response.AssetDir, name)
							}
						}
						response.Assets = append(response.Assets, Asset{
							Name:         name,
							Parent:       response.AssetDir,
							Size:         fileInfo.Size(),
							ModTime:      fileInfo.ModTime(),
							CreationTime: CreationTime(absolutePath, fileInfo),
						})
					}
				}
			}
		case "output":
			if isEditable {
				next, _, _ := strings.Cut(tail, "/")
				if next == "posts" {
					response.URL = template.URL(response.ContentBaseURL + "/" + path.Dir(tail) + "/")
					response.BelongsTo = path.Dir(tail) + ".md"
				} else if next != "themes" {
					dir := path.Dir(tail)
					if dir == "." {
						response.URL = template.URL(response.ContentBaseURL)
						response.BelongsTo = "pages/index.html"
					} else {
						response.URL = template.URL(response.ContentBaseURL + "/" + dir + "/")
						response.BelongsTo = path.Join("pages", dir+".html")
					}
				}
			}
		}

		if response.PinnedAssets == nil {
			response.PinnedAssets = []Asset{}
		}
		if response.Assets == nil {
			response.Assets = []Asset{}
		}
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

		if !isEditable {
			ServeFile(w, r, path.Base(filePath), fileInfo.Size(), fileType, file, "no-cache")
			return
		}

		referer := nbrew.GetReferer(r)
		clipboard := make(url.Values)
		isInClipboard := make(map[string]bool)
		cookie, _ := r.Cookie("clipboard")
		if cookie != nil {
			values, err := url.ParseQuery(cookie.Value)
			if err == nil && values.Get("sitePrefix") == sitePrefix {
				if values.Has("cut") {
					clipboard.Set("cut", "")
				}
				clipboard.Set("sitePrefix", values.Get("sitePrefix"))
				clipboard.Set("parent", values.Get("parent"))
				for _, name := range values["name"] {
					if isInClipboard[name] {
						continue
					}
					clipboard.Add("name", name)
					isInClipboard[name] = true
				}
			}
		}
		funcMap := map[string]any{
			"join":                  path.Join,
			"dir":                   path.Dir,
			"base":                  path.Base,
			"ext":                   path.Ext,
			"hasPrefix":             strings.HasPrefix,
			"hasSuffix":             strings.HasSuffix,
			"trimPrefix":            strings.TrimPrefix,
			"trimSuffix":            strings.TrimSuffix,
			"joinStrings":           strings.Join,
			"humanReadableFileSize": HumanReadableFileSize,
			"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
			"referer":               func() string { return referer },
			"clipboard":             func() url.Values { return clipboard },
			"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"getFileType": func(name string) FileType {
				return AllowedFileTypes[path.Ext(name)]
			},
			"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
				var b strings.Builder
				segments := strings.Split(filePath, "/")
				if sitePrefix != "" {
					segments = append([]string{sitePrefix}, segments...)
				}
				for i := 0; i < len(segments)-1; i++ {
					if segments[i] == "" {
						continue
					}
					if b.Len() > 0 {
						b.WriteString("\n<span class='mh1'>&boxv;</span>")
					}
					href := "/files/" + path.Join(segments[:i+1]...) + "/"
					b.WriteString("<a href='" + href + "'>" + segments[i] + "</a>")
				}
				return template.HTML(b.String())
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.AssetDir != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
			},
			"jsonArray": func(s []string) (string, error) {
				b, err := json.Marshal(s)
				if err != nil {
					return "", err
				}
				return string(b), nil
			},
		}
		tmpl, err := template.New("file.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/file.html")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.ExecuteTemplate(w, r, tmpl, &response)
	case "POST":
		if user.DisableReason != "" {
			nbrew.AccountDisabled(w, r, user.DisableReason)
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
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "file",
				},
				"regenerationStats": response.RegenerationStats,
				"uploadCount":       response.UploadCount,
				"uploadSize":        response.UploadSize,
				"filesExist":        response.FilesExist,
				"filesTooBig":       response.FilesTooBig,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, urlReplacer.Replace("/"+path.Join("files", sitePrefix, filePath)), http.StatusFound)
		}

		if !isEditable {
			nbrew.MethodNotAllowed(w, r)
			return
		}

		var err error
		var reader *multipart.Reader
		var storageRemaining *atomic.Int64
		var uploadCount, uploadSize atomic.Int64
		var filesExist, filesTooBig []string
		var request struct {
			Content            string
			RegenerateParent   bool
			RegeneratePostList bool
			RegenerateSite     bool
		}
		var isDatabaseFS bool
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			isDatabaseFS = v.As(&DatabaseFS{})
		}
		if nbrew.DB != nil && isDatabaseFS && user.StorageLimit >= 0 {
			storageUsed, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM site" +
					" JOIN site_owner ON site_owner.site_id = site.site_id" +
					" WHERE site_owner.user_id = {userID}",
				Values: []any{
					sq.UUIDParam("userID", user.UserID),
				},
			}, func(row *sq.Row) int64 {
				return row.Int64("sum(CASE WHEN site.storage_used IS NOT NULL AND site.storage_used > 0 THEN site.storage_used ELSE 0 END)")
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			storageRemaining = &atomic.Int64{}
			storageRemaining.Store(user.StorageLimit - storageUsed)
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := r.ParseForm()
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
			request.Content = r.Form.Get("content")
			request.RegenerateParent, _ = strconv.ParseBool(r.Form.Get("regenerateParent"))
			request.RegeneratePostList, _ = strconv.ParseBool(r.Form.Get("regeneratePostList"))
			request.RegenerateSite, _ = strconv.ParseBool(r.Form.Get("regenerateSite"))
		case "multipart/form-data":
			reader, err = r.MultipartReader()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if head == "pages" || head == "posts" {
				var outputDir string
				if head == "posts" {
					outputDir = path.Join(sitePrefix, "output/posts", strings.TrimSuffix(tail, ".md"))
				} else {
					if filePath == "pages/index.html" {
						outputDir = path.Join(sitePrefix, "output")
					} else {
						outputDir = path.Join(sitePrefix, "output", strings.TrimSuffix(tail, ".html"))
					}
				}
				tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
					writerCtx, cancelWriter := context.WithCancel(ctx)
					defer cancelWriter()
					writer, err := nbrew.FS.WithContext(writerCtx).OpenWriter(filePath, 0644)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							return err
						}
						err := nbrew.FS.WithContext(writerCtx).MkdirAll(path.Dir(filePath), 0755)
						if err != nil {
							return err
						}
						writer, err = nbrew.FS.WithContext(writerCtx).OpenWriter(filePath, 0644)
						if err != nil {
							return err
						}
					}
					defer func() {
						cancelWriter()
						writer.Close()
					}()
					var n int64
					if storageRemaining != nil {
						limitedWriter := &LimitedWriter{
							W:   writer,
							N:   storageRemaining.Load(),
							Err: ErrStorageLimitExceeded,
						}
						n, err = io.Copy(limitedWriter, reader)
						storageRemaining.Add(-n)
					} else {
						n, err = io.Copy(writer, reader)
					}
					if err != nil {
						return err
					}
					err = writer.Close()
					if err != nil {
						return err
					}
					uploadCount.Add(1)
					uploadSize.Add(n)
					return nil
				}
				var monotonicCounter atomic.Int64
				group, groupctx := errgroup.WithContext(r.Context())
				for {
					part, err := reader.NextPart()
					if err != nil {
						if err == io.EOF {
							break
						}
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					formName := part.FormName()
					if formName != "file" {
						var maxBytesErr *http.MaxBytesError
						var b strings.Builder
						_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
						if err != nil {
							if errors.As(err, &maxBytesErr) {
								nbrew.BadRequest(w, r, err)
								return
							}
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
						switch formName {
						case "content":
							request.Content = b.String()
						case "regenerateParent":
							request.RegenerateParent, _ = strconv.ParseBool(b.String())
						case "regeneratePostList":
							request.RegeneratePostList, _ = strconv.ParseBool(b.String())
						case "regenerateSite":
							request.RegenerateSite, _ = strconv.ParseBool(b.String())
						}
						continue
					}
					_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
					if err != nil {
						continue
					}
					fileName := params["filename"]
					if fileName == "" || strings.Contains(fileName, "/") {
						continue
					}
					fileName = filenameSafe(fileName)
					fileType := AllowedFileTypes[path.Ext(fileName)]
					switch head {
					case "pages":
						if !fileType.Has(AttributeImg) && fileType.Ext != ".css" && fileType.Ext != ".js" && fileType.Ext != ".md" {
							continue
						}
					case "posts":
						if !fileType.Has(AttributeImg) {
							continue
						}
					}
					if fileType.Has(AttributeImg) {
						if user.UserFlags["NoUploadImage"] {
							continue
						}
						if strings.TrimSuffix(fileName, fileType.Ext) == "image" {
							var timestamp [8]byte
							now := time.Now()
							monotonicCounter.CompareAndSwap(0, now.Unix())
							binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), monotonicCounter.Add(1))))
							timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
							fileName = "image-" + timestampSuffix + fileType.Ext
						}
						filePath := path.Join(outputDir, fileName)
						_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), filePath)
						if err != nil {
							if !errors.Is(err, fs.ErrNotExist) {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
						} else {
							filesExist = append(filesExist, fileName)
							continue
						}
						if !fileType.Has(AttributeObject) {
							err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
							if err != nil {
								var maxBytesErr *http.MaxBytesError
								if errors.As(err, &maxBytesErr) {
									filesTooBig = append(filesTooBig, fileName)
									continue
								}
								if errors.Is(err, ErrStorageLimitExceeded) {
									nbrew.StorageLimitExceeded(w, r)
									return
								}
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
						} else {
							if nbrew.ImgCmd == "" {
								err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
								if err != nil {
									var maxBytesErr *http.MaxBytesError
									if errors.As(err, &maxBytesErr) {
										filesTooBig = append(filesTooBig, fileName)
										continue
									}
									if errors.Is(err, ErrStorageLimitExceeded) {
										nbrew.StorageLimitExceeded(w, r)
										return
									}
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
							} else {
								cmdPath, err := exec.LookPath(nbrew.ImgCmd)
								if err != nil {
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
								id := NewID()
								inputPath := path.Join(tempDir, id.String()+"-input"+fileType.Ext)
								outputPath := path.Join(tempDir, id.String()+"-output"+fileType.Ext)
								input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
								if err != nil {
									if !errors.Is(err, fs.ErrNotExist) {
										nbrew.GetLogger(r.Context()).Error(err.Error())
										nbrew.InternalServerError(w, r, err)
										return
									}
									err := os.MkdirAll(filepath.Dir(inputPath), 0755)
									if err != nil {
										nbrew.GetLogger(r.Context()).Error(err.Error())
										nbrew.InternalServerError(w, r, err)
										return
									}
									input, err = os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
									if err != nil {
										nbrew.GetLogger(r.Context()).Error(err.Error())
										nbrew.InternalServerError(w, r, err)
										return
									}
								}
								_, err = io.Copy(input, http.MaxBytesReader(nil, part, fileType.SizeLimit))
								if err != nil {
									os.Remove(inputPath)
									var maxBytesErr *http.MaxBytesError
									if errors.As(err, &maxBytesErr) {
										filesTooBig = append(filesTooBig, fileName)
										continue
									}
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
								err = input.Close()
								if err != nil {
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
								group.Go(func() (err error) {
									defer stacktrace.RecoverPanic(&err)
									defer os.Remove(inputPath)
									defer os.Remove(outputPath)
									cmd := exec.CommandContext(groupctx, cmdPath, inputPath, outputPath)
									cmd.Stdout = os.Stdout
									cmd.Stderr = os.Stderr
									err = cmd.Run()
									if err != nil {
										return stacktrace.New(err)
									}
									output, err := os.Open(outputPath)
									if err != nil {
										return stacktrace.New(err)
									}
									defer output.Close()
									err = writeFile(groupctx, filePath, output)
									if err != nil {
										return err
									}
									return nil
								})
							}
						}
					} else {
						filePath := path.Join(outputDir, fileName)
						_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), filePath)
						if err != nil {
							if !errors.Is(err, fs.ErrNotExist) {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
						} else {
							filesExist = append(filesExist, fileName)
							continue
						}
						err = writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
						if err != nil {
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								filesTooBig = append(filesTooBig, fileName)
								continue
							}
							if errors.Is(err, ErrStorageLimitExceeded) {
								nbrew.StorageLimitExceeded(w, r)
								return
							}
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
					}
				}
				err = group.Wait()
				if err != nil {
					if errors.Is(err, ErrStorageLimitExceeded) {
						nbrew.StorageLimitExceeded(w, r)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				for {
					part, err := reader.NextPart()
					if err != nil {
						if err == io.EOF {
							break
						}
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					formName := part.FormName()
					var maxBytesErr *http.MaxBytesError
					var b strings.Builder
					_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
					if err != nil {
						if errors.As(err, &maxBytesErr) {
							nbrew.BadRequest(w, r, err)
							return
						}
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					switch formName {
					case "content":
						request.Content = b.String()
					case "regenerateParent":
						request.RegenerateParent, _ = strconv.ParseBool(b.String())
					case "regeneratePostList":
						request.RegeneratePostList, _ = strconv.ParseBool(b.String())
					case "regenerateSite":
						request.RegenerateSite, _ = strconv.ParseBool(b.String())
					}
				}
			}
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			ContentBaseURL: nbrew.ContentBaseURL(sitePrefix),
			SitePrefix:     sitePrefix,
			FilePath:       filePath,
			IsDir:          fileInfo.IsDir(),
			ModTime:        time.Now(),
			Content:        request.Content,
			UploadCount:    uploadCount.Load(),
			UploadSize:     uploadSize.Load(),
			FilesExist:     filesExist,
			FilesTooBig:    filesTooBig,
		}
		if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.CreationTime = databaseFileInfo.CreationTime
		} else {
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
				}
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}

		writerCtx, cancelWriter := context.WithCancel(r.Context())
		defer cancelWriter()
		writer, err := nbrew.FS.WithContext(writerCtx).OpenWriter(path.Join(sitePrefix, filePath), 0644)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer func() {
			cancelWriter()
			writer.Close()
		}()
		var n int64
		if storageRemaining != nil {
			limitedWriter := &LimitedWriter{
				W:   writer,
				N:   storageRemaining.Load(),
				Err: ErrStorageLimitExceeded,
			}
			n, err = io.Copy(limitedWriter, strings.NewReader(response.Content))
			storageRemaining.Add(-n)
		} else {
			n, err = io.Copy(writer, strings.NewReader(response.Content))
		}
		if err != nil {
			if errors.Is(err, ErrStorageLimitExceeded) {
				nbrew.StorageLimitExceeded(w, r)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		switch head {
		case "pages":
			siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
				FS:                 nbrew.FS,
				ContentDomain:      nbrew.ContentDomain,
				ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
				CDNDomain:          nbrew.CDNDomain,
				SitePrefix:         sitePrefix,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			var count atomic.Int64
			var templateErrPtr atomic.Pointer[TemplateError]
			group, groupctx := errgroup.WithContext(r.Context())
			startedAt := time.Now()
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				err = siteGen.GeneratePage(groupctx, filePath, response.Content, response.ModTime, response.CreationTime)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				count.Add(1)
				return nil
			})
			if request.RegenerateParent {
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					var parentPage string
					dir := path.Dir(filePath)
					if dir == "pages" {
						parentPage = "pages/index.html"
					} else {
						parentPage = dir + ".html"
					}
					file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, parentPage))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							return nil
						}
						return err
					}
					fileInfo, err := file.Stat()
					if err != nil {
						return err
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						return err
					}
					content := b.String()
					var creationTime time.Time
					if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
						creationTime = databaseFileInfo.CreationTime
					} else {
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, parentPage)
							}
						}
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					err = siteGen.GeneratePage(groupctx, parentPage, content, fileInfo.ModTime(), creationTime)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					count.Add(1)
					return nil
				})
			}
			err = group.Wait()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = count.Load()
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			if ptr := templateErrPtr.Load(); ptr != nil {
				response.RegenerationStats.TemplateError = *ptr
			}
		case "posts":
			siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
				FS:                 nbrew.FS,
				ContentDomain:      nbrew.ContentDomain,
				ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
				CDNDomain:          nbrew.CDNDomain,
				SitePrefix:         sitePrefix,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			category := path.Dir(tail)
			if category == "." {
				category = ""
			}
			name := path.Base(tail)
			if name == "post.html" {
				startedAt := time.Now()
				tmpl, err := siteGen.PostTemplate(r.Context(), category)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count, err = siteGen.GeneratePosts(r.Context(), category, tmpl)
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else if name == "postlist.html" {
				startedAt := time.Now()
				tmpl, err := siteGen.PostListTemplate(r.Context(), category)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else if strings.HasSuffix(name, ".md") {
				var count atomic.Int64
				var templateErrPtr atomic.Pointer[TemplateError]
				group, groupctx := errgroup.WithContext(r.Context())
				startedAt := time.Now()
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					tmpl, err := siteGen.PostTemplate(groupctx, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					err = siteGen.GeneratePost(r.Context(), filePath, response.Content, response.ModTime, response.CreationTime, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					count.Add(1)
					return nil
				})
				if request.RegeneratePostList {
					group.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						tmpl, err := siteGen.PostListTemplate(groupctx, category)
						if err != nil {
							var templateErr TemplateError
							if errors.As(err, &templateErr) {
								templateErrPtr.CompareAndSwap(nil, &templateErr)
								return nil
							}
							return err
						}
						n, err := siteGen.GeneratePostList(groupctx, category, tmpl)
						if err != nil {
							var templateErr TemplateError
							if errors.As(err, &templateErr) {
								templateErrPtr.CompareAndSwap(nil, &templateErr)
								return nil
							}
							return err
						}
						count.Add(n)
						return nil
					})
				}
				err := group.Wait()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count = count.Load()
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if ptr := templateErrPtr.Load(); ptr != nil {
					response.RegenerationStats.TemplateError = *ptr
				}
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				if request.RegenerateSite {
					regenerationStats, err := nbrew.RegenerateSite(r.Context(), sitePrefix)
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					response.RegenerationStats = regenerationStats
				}
			} else if next != "posts" {
				if fileType.Ext == ".md" {
					var parentPage string
					dir := path.Dir(tail)
					if dir == "." {
						parentPage = "pages/index.html"
					} else {
						parentPage = path.Join("pages", dir+".html")
					}
					file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, parentPage))
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					fileInfo, err := file.Stat()
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					var creationTime time.Time
					if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
						creationTime = databaseFileInfo.CreationTime
					} else {
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
							}
						}
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
						FS:                 nbrew.FS,
						ContentDomain:      nbrew.ContentDomain,
						ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
						CDNDomain:          nbrew.CDNDomain,
						SitePrefix:         sitePrefix,
					})
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					startedAt := time.Now()
					err = siteGen.GeneratePage(r.Context(), parentPage, b.String(), fileInfo.ModTime(), creationTime)
					if err != nil {
						if errors.As(err, &response.RegenerationStats.TemplateError) {
							writeResponse(w, r, response)
							return
						}
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					response.RegenerationStats.Count = 1
					response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				}
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
