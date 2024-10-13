package notebrew

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
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

func (nbrew *Notebrew) applytheme(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent            string `json:"parent"`
		ApplyIndexHTML    bool   `json:"applyIndexHTML"`
		Apply404HTML      bool   `json:"apply404HTML"`
		ApplyPostHTML     bool   `json:"applyPostHTML"`
		ApplyPostListHTML bool   `json:"applyPostListHTML"`
		ForAllCategories  bool   `json:"forAllCategories"`
		ForCategory       string `json:"forCategory"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		Categories        []string          `json:"categories"`
		Parent            string            `json:"parent"`
		HasIndexHTML      bool              `json:"hasIndexHTML"`
		Has404HTML        bool              `json:"has404HTML"`
		HasPostHTML       bool              `json:"hasPostHTML"`
		HasPostListHTML   bool              `json:"hasPostListHTML"`
		ApplyIndexHTML    bool              `json:"applyIndexHTML"`
		Apply404HTML      bool              `json:"apply404HTML"`
		ApplyPostHTML     bool              `json:"applyPostHTML"`
		ApplyPostListHTML bool              `json:"applyPostListHTML"`
		ForAllCategories  bool              `json:"forAllCategories"`
		ForCategory       string            `json:"forCategory"`
		Error             string            `json:"error"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
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
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("applytheme.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/applytheme.html")
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
		response.SitePrefix = sitePrefix
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.Categories = []string{""}
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		if head != "output" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		next, _, _ := strings.Cut(tail, "/")
		if next != "themes" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
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
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, "index.html"))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			if fileInfo.IsDir() {
				return nil
			}
			response.HasIndexHTML = true
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, "404.html"))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			if fileInfo.IsDir() {
				return nil
			}
			response.Has404HTML = true
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, "post.html"))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			if fileInfo.IsDir() {
				return nil
			}
			response.HasPostHTML = true
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, "postlist.html"))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			if fileInfo.IsDir() {
				return nil
			}
			response.HasPostListHTML = true
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			databaseFS, ok := &DatabaseFS{}, false
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				ok = v.As(&databaseFS)
			}
			if ok {
				categories, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND is_dir",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, "posts")),
					},
				}, func(row *sq.Row) string {
					return path.Base(row.String("file_path"))
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Categories = append(response.Categories, categories...)
			} else {
				err := fs.WalkDir(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, "posts"), func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if dirEntry.IsDir() {
						response.Categories = append(response.Categories, path.Base(filePath))
					}
					return nil
				})
				if err != nil {
					return stacktrace.New(err)
				}
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
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
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join(sitePrefix, "files/applytheme")+"/", http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "applytheme",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, urlReplacer.Replace("/"+path.Join("files", sitePrefix, response.Parent)), http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
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
			request.Parent = r.Form.Get("parent")
			request.ApplyIndexHTML, _ = strconv.ParseBool(r.Form.Get("applyIndexHTML"))
			request.Apply404HTML, _ = strconv.ParseBool(r.Form.Get("apply404HTML"))
			request.ApplyPostHTML, _ = strconv.ParseBool(r.Form.Get("applyPostHTML"))
			request.ApplyPostListHTML, _ = strconv.ParseBool(r.Form.Get("applyPostListHTML"))
			request.ForAllCategories, _ = strconv.ParseBool(r.Form.Get("forAllCategories"))
			request.ForCategory = r.Form.Get("forCategory")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:            path.Clean(strings.Trim(request.Parent, "/")),
			ApplyIndexHTML:    request.ApplyIndexHTML,
			Apply404HTML:      request.Apply404HTML,
			ApplyPostHTML:     request.ApplyPostHTML,
			ApplyPostListHTML: request.ApplyPostListHTML,
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		if head != "output" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		nextHead, nextTail, _ := strings.Cut(tail, "/")
		if nextHead != "themes" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
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
		if !response.ApplyIndexHTML && !response.Apply404HTML && !response.ApplyPostHTML && !response.ApplyPostListHTML {
			writeResponse(w, r, response)
			return
		}
		if request.ForAllCategories {
			response.ForAllCategories = true
			response.Categories = []string{""}
			databaseFS, ok := &DatabaseFS{}, false
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				ok = v.As(&databaseFS)
			}
			if ok {
				categories, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND is_dir",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, "posts")),
					},
				}, func(row *sq.Row) string {
					return path.Base(row.String("file_path"))
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.Categories = append(response.Categories, categories...)
			} else {
				err := fs.WalkDir(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "posts"), func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if dirEntry.IsDir() {
						response.Categories = append(response.Categories, path.Base(filePath))
					}
					return nil
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			}
		} else {
			category := filepath.ToSlash(request.ForCategory)
			if strings.Contains(category, "/") {
				response.Error = "InvalidCategory"
				writeResponse(w, r, response)
				return
			}
			_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "posts", request.ForCategory))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidCategory"
					writeResponse(w, r, response)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.ForCategory = category
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
		var regenerationCount atomic.Int64
		var templateErrPtr atomic.Pointer[TemplateError]
		startedAt := time.Now()
		group, groupctx := errgroup.WithContext(r.Context())
		if response.ApplyIndexHTML {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, response.Parent, "index.html"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return stacktrace.New(err)
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return stacktrace.New(err)
				}
				if fileInfo.IsDir() {
					return nil
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return stacktrace.New(err)
				}
				text := b.String()
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
				if err != nil {
					return stacktrace.New(err)
				}
				defer writer.Close()
				_, err = io.Copy(writer, strings.NewReader("{{ template "+strconv.Quote("/"+path.Join("themes", nextTail)+"/index.html")+" $ }}"))
				if err != nil {
					return stacktrace.New(err)
				}
				err = writer.Close()
				if err != nil {
					return stacktrace.New(err)
				}
				creationTime := time.Now()
				err = siteGen.GeneratePage(groupctx, "pages/index.html", text, creationTime, creationTime)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return stacktrace.New(err)
				}
				regenerationCount.Add(1)
				return nil
			})
		}
		if response.Apply404HTML {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, response.Parent, "404.html"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return stacktrace.New(err)
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return stacktrace.New(err)
				}
				if fileInfo.IsDir() {
					return nil
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return stacktrace.New(err)
				}
				text := b.String()
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
				if err != nil {
					return stacktrace.New(err)
				}
				defer writer.Close()
				_, err = io.Copy(writer, strings.NewReader("{{ template "+strconv.Quote("/"+path.Join("themes", nextTail)+"/404.html")+" $ }}"))
				if err != nil {
					return stacktrace.New(err)
				}
				err = writer.Close()
				if err != nil {
					return stacktrace.New(err)
				}
				creationTime := time.Now()
				err = siteGen.GeneratePage(groupctx, "pages/404/index.html", text, creationTime, creationTime)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return stacktrace.New(err)
				}
				regenerationCount.Add(1)
				return nil
			})
		}
		if response.ApplyPostHTML {
			applyPostHTML := func(ctx context.Context, category string) error {
				file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, response.Parent, "post.html"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return stacktrace.New(err)
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return stacktrace.New(err)
				}
				if fileInfo.IsDir() {
					return nil
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return stacktrace.New(err)
				}
				text := b.String()
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts", category, "post.html"), 0644)
				if err != nil {
					return stacktrace.New(err)
				}
				defer writer.Close()
				_, err = io.Copy(writer, strings.NewReader("{{ template "+strconv.Quote("/"+path.Join("themes", nextTail)+"/post.html")+" $ }}"))
				if err != nil {
					return stacktrace.New(err)
				}
				err = writer.Close()
				if err != nil {
					return stacktrace.New(err)
				}
				tmpl, err := siteGen.ParseTemplate(groupctx, path.Join("posts", category, "post.html"), text)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return stacktrace.New(err)
				}
				n, err := siteGen.GeneratePosts(ctx, category, tmpl)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return stacktrace.New(err)
				}
				regenerationCount.Add(n)
				return nil
			}
			if response.ForAllCategories {
				for _, category := range response.Categories {
					category := category
					group.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						return applyPostHTML(groupctx, category)
					})
				}
			} else {
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					return applyPostHTML(groupctx, response.ForCategory)
				})
			}
		}
		if response.ApplyPostListHTML {
			applyPostListHTML := func(ctx context.Context, category string) error {
				file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, response.Parent, "postlist.html"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return stacktrace.New(err)
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return stacktrace.New(err)
				}
				if fileInfo.IsDir() {
					return nil
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return stacktrace.New(err)
				}
				text := b.String()
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts", category, "postlist.html"), 0644)
				if err != nil {
					return stacktrace.New(err)
				}
				defer writer.Close()
				_, err = io.Copy(writer, strings.NewReader("{{ template "+strconv.Quote("/"+path.Join("themes", nextTail)+"/postlist.html")+" $ }}"))
				if err != nil {
					return stacktrace.New(err)
				}
				err = writer.Close()
				if err != nil {
					return stacktrace.New(err)
				}
				tmpl, err := siteGen.ParseTemplate(groupctx, path.Join("posts", category, "postlist.html"), text)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return stacktrace.New(err)
				}
				n, err := siteGen.GeneratePostList(ctx, category, tmpl)
				if err != nil {
					var templateErr TemplateError
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return stacktrace.New(err)
				}
				regenerationCount.Add(n)
				return nil
			}
			if response.ForAllCategories {
				for _, category := range response.Categories {
					category := category
					group.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						return applyPostListHTML(groupctx, category)
					})
				}
			} else {
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					return applyPostListHTML(groupctx, response.ForCategory)
				})
			}
		}
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.RegenerationStats.Count = regenerationCount.Load()
		response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
		if ptr := templateErrPtr.Load(); ptr != nil {
			response.RegenerationStats.TemplateError = *ptr
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
