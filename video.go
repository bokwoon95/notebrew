package notebrew

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) video(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		CDNDomain         string            `json:"cdnDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		FileID            ID                `json:"fileID"`
		FilePath          string            `json:"filePath"`
		IsObject          bool              `json:"isObject"`
		IsDir             bool              `json:"isDir"`
		Size              int64             `json:"size"`
		ModTime           time.Time         `json:"modTime"`
		CreationTime      time.Time         `json:"creationTime"`
		Content           string            `json:"content"`
		ContentType       string            `json:"contentType"`
		URL               template.URL      `json:"url"`
		BelongsTo         string            `json:"belongsTo"`
		PreviousVideoID   ID                `json:"previousVideoID"`
		PreviousVideoName string            `json:"previousVideoName"`
		NextVideoID       ID                `json:"nextVideoID"`
		NextVideoName     string            `json:"nextVideoName"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}

	switch r.Method {
	case "GET", "HEAD":
		if r.Form.Has("raw") {
			var values map[string]any
			fsys := nbrew.FS.WithContext(r.Context())
			if v, ok := fsys.(interface {
				WithValues(map[string]any) FS
			}); ok {
				values = map[string]any{
					"httprange": r.Header.Get("Range"),
				}
				fsys = v.WithValues(values)
			}
			file, err := fsys.Open(path.Join(".", sitePrefix, filePath))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					nbrew.NotFound(w, r)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileType, ok := AllowedFileTypes[path.Ext(filePath)]
			if !ok {
				nbrew.NotFound(w, r)
				return
			}
			if contentRange, ok := values["httpcontentrange"].(string); ok && contentRange != "" {
				w.Header().Set("Content-Type", fileType.ContentType)
				w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(path.Base(filePath)))
				w.Header().Set("Cache-Control", "max-age=2592000, stale-while-revalidate=31536000" /* 1 month, 1 year */)
				w.Header().Set("Accept-Ranges", "bytes")
				w.Header().Set("Content-Range", contentRange)
				w.WriteHeader(http.StatusPartialContent)
				_, err = io.Copy(w, file)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			ServeFile(w, r, path.Base(filePath), fileInfo.Size(), fileType, file, "max-age=2592000, stale-while-revalidate=31536000" /* 1 month, 1 year */)
			return
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.SitePrefix = sitePrefix
		response.CDNDomain = nbrew.CDNDomain
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.FileID = databaseFileInfo.FileID
			response.ModTime = databaseFileInfo.ModTime()
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
		fileType := AllowedFileTypes[path.Ext(filePath)]
		response.IsObject = fileType.Has(AttributeObject)
		response.Size = fileInfo.Size()
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		response.ContentType = fileType.ContentType
		databaseFS, ok := &DatabaseFS{}, false
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			ok = v.As(&databaseFS)
		}
		if ok {
			response.IsDatabaseFS = true
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				extFilter := sq.Expr("1 = 1")
				if len(videoExts) > 0 {
					var b strings.Builder
					args := make([]any, 0, len(videoExts))
					b.WriteString("(")
					for i, ext := range videoExts {
						if i > 0 {
							b.WriteString(" OR ")
						}
						b.WriteString("file_path LIKE {} ESCAPE '\\'")
						args = append(args, "%"+wildcardReplacer.Replace(ext))
					}
					b.WriteString(")")
					extFilter = sq.Expr(b.String(), args...)
				}
				result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND file_path < {filePath}" +
						" AND {extFilter}" +
						" ORDER BY file_path DESC" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(response.SitePrefix, path.Dir(response.FilePath))),
						sq.StringParam("filePath", path.Join(response.SitePrefix, response.FilePath)),
						sq.Param("extFilter", extFilter),
					},
				}, func(row *sq.Row) (result struct {
					FileID   ID
					FilePath string
				}) {
					result.FileID = row.UUID("file_id")
					result.FilePath = row.String("file_path")
					return result
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				response.PreviousVideoID = result.FileID
				response.PreviousVideoName = path.Base(result.FilePath)
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				content, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
					},
				}, func(row *sq.Row) string {
					return row.String("text")
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Content = strings.TrimSpace(content)
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				extFilter := sq.Expr("1 <> 1")
				if len(videoExts) > 0 {
					var b strings.Builder
					args := make([]any, 0, len(videoExts))
					b.WriteString("(")
					for i, ext := range videoExts {
						if i > 0 {
							b.WriteString(" OR ")
						}
						b.WriteString("file_path LIKE {} ESCAPE '\\'")
						args = append(args, "%"+wildcardReplacer.Replace(ext))
					}
					b.WriteString(")")
					extFilter = sq.Expr(b.String(), args...)
				}
				result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND file_path > {filePath}" +
						" AND {extFilter}" +
						" ORDER BY file_path ASC" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(response.SitePrefix, path.Dir(response.FilePath))),
						sq.StringParam("filePath", path.Join(response.SitePrefix, response.FilePath)),
						sq.Param("extFilter", extFilter),
					},
				}, func(row *sq.Row) (result struct {
					FileID   ID
					FilePath string
				}) {
					result.FileID = row.UUID("file_id")
					result.FilePath = row.String("file_path")
					return result
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				response.NextVideoID = result.FileID
				response.NextVideoName = path.Base(result.FilePath)
				return nil
			})
			err = group.Wait()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		head, tail, _ := strings.Cut(filePath, "/")
		if head == "output" {
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
					response.URL = template.URL(response.ContentBaseURL + "/" + path.Join("pages", dir) + "/")
					response.BelongsTo = path.Join("pages", dir+".html")
				}
			}
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
		referer := nbrew.GetReferer(r)
		funcMap := map[string]any{
			"join":                  path.Join,
			"dir":                   path.Dir,
			"base":                  path.Base,
			"ext":                   path.Ext,
			"hasPrefix":             strings.HasPrefix,
			"hasSuffix":             strings.HasSuffix,
			"trimPrefix":            strings.TrimPrefix,
			"trimSuffix":            strings.TrimSuffix,
			"humanReadableFileSize": HumanReadableFileSize,
			"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
			"referer":               func() string { return referer },
			"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
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
					b.WriteString("<a href='" + template.HTMLEscapeString(href) + "'>" + template.HTMLEscapeString(segments[i]) + "</a>")
				}
				return template.HTML(b.String())
			},
		}
		tmpl, err := template.New("video.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/video.html")
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
					"from": "video",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, urlReplacer.Replace("/"+path.Join("files", sitePrefix, filePath)), http.StatusFound)
		}

		response := Response{}
		databaseFS, ok := &DatabaseFS{}, false
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			ok = v.As(&databaseFS)
		}
		if !ok {
			writeResponse(w, r, response)
			return
		}

		var request struct {
			Content            string
			RegeneratePostList bool
			RegenerateSite     bool
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
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
			request.Content = r.Form.Get("content")
			request.RegeneratePostList, _ = strconv.ParseBool(r.Form.Get("regeneratePostList"))
			request.RegenerateSite, _ = strconv.ParseBool(r.Form.Get("regenerateSite"))
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response.Content = strings.TrimSpace(request.Content)
		_, err := sq.Exec(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "UPDATE files SET text = {content}, mod_time = {modTime} WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("content", response.Content),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		head, tail, _ := strings.Cut(filePath, "/")
		if head == "output" {
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
			} else if next == "posts" {
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
				response.BelongsTo = path.Dir(tail) + ".md"
				category := path.Dir(strings.TrimPrefix(response.BelongsTo, "posts/"))
				if category == "." {
					category = ""
				}
				startedAt := time.Now()
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					var text string
					var creationTime time.Time
					databaseFS, ok := &DatabaseFS{}, false
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						ok = v.As(&databaseFS)
					}
					if ok {
						result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
							Dialect: databaseFS.Dialect,
							Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
							Values: []any{
								sq.StringParam("filePath", path.Join(sitePrefix, response.BelongsTo)),
							},
						}, func(row *sq.Row) (result struct {
							Text         string
							CreationTime time.Time
						}) {
							result.Text = row.String("text")
							result.CreationTime = row.Time("creation_time")
							return result
						})
						if err != nil {
							return stacktrace.New(err)
						}
						text = result.Text
						creationTime = result.CreationTime
					} else {
						file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, response.BelongsTo))
						if err != nil {
							return err
						}
						defer file.Close()
						fileInfo, err := file.Stat()
						if err != nil {
							return stacktrace.New(err)
						}
						var b strings.Builder
						b.Grow(int(fileInfo.Size()))
						_, err = io.Copy(&b, file)
						if err != nil {
							return stacktrace.New(err)
						}
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, response.BelongsTo)
							}
						}
						text = b.String()
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					tmpl, err := siteGen.PostTemplate(groupctx, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					err = siteGen.GeneratePost(groupctx, response.BelongsTo, text, time.Now(), creationTime, tmpl)
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
			} else {
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
				var text string
				var modTime, creationTime time.Time
				dir := path.Dir(tail)
				if dir == "." {
					response.BelongsTo = "pages/index.html"
				} else {
					response.BelongsTo = path.Join("pages", path.Dir(tail)+".html")
				}
				databaseFS, ok := &DatabaseFS{}, false
				switch v := nbrew.FS.(type) {
				case interface{ As(any) bool }:
					ok = v.As(&databaseFS)
				}
				if ok {
					result, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
						Values: []any{
							sq.StringParam("filePath", path.Join(sitePrefix, response.BelongsTo)),
						},
					}, func(row *sq.Row) (result struct {
						Text         string
						ModTime      time.Time
						CreationTime time.Time
					}) {
						result.Text = row.String("text")
						result.ModTime = row.Time("mod_time")
						result.CreationTime = row.Time("creation_time")
						return result
					})
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					text = result.Text
					modTime = result.ModTime
					creationTime = result.CreationTime
				} else {
					file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, response.BelongsTo))
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					text = b.String()
					modTime = fileInfo.ModTime()
					var absolutePath string
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						var directoryFS *DirectoryFS
						if v.As(&directoryFS) {
							absolutePath = path.Join(directoryFS.RootDir, response.SitePrefix, response.BelongsTo)
						}
					}
					creationTime = CreationTime(absolutePath, fileInfo)
				}
				startedAt := time.Now()
				err = siteGen.GeneratePage(r.Context(), response.BelongsTo, text, modTime, creationTime)
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
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
