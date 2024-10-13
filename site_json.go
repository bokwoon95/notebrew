package notebrew

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

type SiteConfig struct {
	LanguageCode    string           `json:"languageCode"`
	Title           string           `json:"title"`
	Tagline         string           `json:"tagline"`
	Emoji           string           `json:"emoji"`
	Favicon         string           `json:"favicon"`
	CodeStyle       string           `json:"codeStyle"`
	TimezoneOffset  string           `json:"timezoneOffset"`
	Description     string           `json:"description"`
	NavigationLinks []NavigationLink `json:"navigationLinks"`
}

func (nbrew *Notebrew) siteJSON(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type NavigationLink struct {
		Name string       `json:"name"`
		URL  template.URL `json:"url"`
	}
	type Request struct {
		LanguageCode    string           `json:"languageCode"`
		Title           string           `json:"title"`
		Tagline         string           `json:"tagline"`
		Emoji           string           `json:"emoji"`
		Favicon         string           `json:"favicon"`
		CodeStyle       string           `json:"codeStyle"`
		TimezoneOffset  string           `json:"timezoneOffset"`
		Description     string           `json:"description"`
		NavigationLinks []NavigationLink `json:"navigationLinks"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		LanguageCode      string            `json:"languageCode"`
		Title             string            `json:"title"`
		Tagline           string            `json:"tagline"`
		Emoji             string            `json:"emoji"`
		Favicon           string            `json:"favicon"`
		CodeStyle         string            `json:"codeStyle"`
		TimezoneOffset    string            `json:"timezoneOffset"`
		Description       string            `json:"description"`
		NavigationLinks   []NavigationLink  `json:"navigationLinks"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}
	normalizeRequest := func(request Request) Request {
		if !languageCodes[request.LanguageCode] {
			request.LanguageCode = "en"
		}
		if request.Emoji == "" {
			request.Emoji = "☕"
		}
		if !chromaStyles[request.CodeStyle] {
			request.CodeStyle = "onedark"
		}
		if !timezoneOffsets[request.TimezoneOffset] {
			request.TimezoneOffset = "+00:00"
		}
		return request
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
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"contains":              strings.Contains,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"chromaStyles":          func() map[string]bool { return chromaStyles },
				"timezoneOffsets":       func() map[string]bool { return timezoneOffsets },
				"languageCodes":         func() map[string]bool { return languageCodes },
				"incr":                  func(n int) int { return n + 1 },
				"getLanguageName": func(languageCode string) string {
					return languageNames[languageCode]
				},
			}
			tmpl, err := template.New("site_json.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/site_json.html")
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
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			response.IsDatabaseFS = v.As(&DatabaseFS{})
		}
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		b, err := fs.ReadFile(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "site.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		var request Request
		if len(b) > 0 {
			err := json.Unmarshal(b, &request)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		request = normalizeRequest(request)
		response.LanguageCode = request.LanguageCode
		response.Title = request.Title
		response.Tagline = request.Tagline
		response.Emoji = request.Emoji
		response.Favicon = request.Favicon
		response.CodeStyle = request.CodeStyle
		response.TimezoneOffset = request.TimezoneOffset
		response.Description = request.Description
		response.NavigationLinks = request.NavigationLinks
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
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "site.json",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "site.json"), http.StatusFound)
		}

		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
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
			request.LanguageCode = r.Form.Get("languageCode")
			request.Title = r.Form.Get("title")
			request.Tagline = r.Form.Get("tagline")
			request.Emoji = r.Form.Get("emoji")
			request.Favicon = r.Form.Get("favicon")
			request.CodeStyle = r.Form.Get("codeStyle")
			request.TimezoneOffset = r.Form.Get("timezoneOffset")
			request.Description = r.Form.Get("description")
			navigationLinkNames := r.Form["navigationLinkName"]
			navigationLinkURLs := r.Form["navigationLinkURL"]
			for i := range navigationLinkNames {
				if i >= len(navigationLinkURLs) {
					break
				}
				request.NavigationLinks = append(request.NavigationLinks, NavigationLink{
					Name: navigationLinkNames[i],
					URL:  template.URL(navigationLinkURLs[i]),
				})
			}
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		request = normalizeRequest(request)
		b, err := json.MarshalIndent(&request, "", "  ")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, bytes.NewReader(b))
		if err != nil {
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
		regenerationStats, err := nbrew.RegenerateSite(r.Context(), sitePrefix)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response := Response{
			ContentBaseURL:    nbrew.ContentBaseURL(sitePrefix),
			UserID:            user.UserID,
			Username:          user.Username,
			SitePrefix:        sitePrefix,
			LanguageCode:      request.LanguageCode,
			Title:             request.Title,
			Tagline:           request.Tagline,
			Emoji:             request.Emoji,
			Favicon:           request.Favicon,
			CodeStyle:         request.CodeStyle,
			Description:       request.Description,
			NavigationLinks:   request.NavigationLinks,
			RegenerationStats: regenerationStats,
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}

type RegenerationStats struct {
	Count         int64         `json:"count"`
	TimeTaken     string        `json:"timeTaken"`
	TemplateError TemplateError `json:"templateError"`
}

func (nbrew *Notebrew) RegenerateSite(ctx context.Context, sitePrefix string) (RegenerationStats, error) {
	siteGen, err := NewSiteGenerator(ctx, SiteGeneratorConfig{
		FS:                 nbrew.FS,
		ContentDomain:      nbrew.ContentDomain,
		ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
		CDNDomain:          nbrew.CDNDomain,
		SitePrefix:         sitePrefix,
	})
	if err != nil {
		return RegenerationStats{}, stacktrace.New(err)
	}
	var regenerationStats RegenerationStats
	pagesDir := path.Join(sitePrefix, "pages")
	postsDir := path.Join(sitePrefix, "posts")
	postTemplate, err := siteGen.PostTemplate(ctx, "")
	if err != nil {
		if errors.As(err, &regenerationStats.TemplateError) {
			return regenerationStats, nil
		}
		return regenerationStats, stacktrace.New(err)
	}
	postTemplates := map[string]*template.Template{
		"": postTemplate,
	}
	postListTemplate, err := siteGen.PostListTemplate(ctx, "")
	if err != nil {
		if errors.As(err, &regenerationStats.TemplateError) {
			return regenerationStats, nil
		}
		return regenerationStats, stacktrace.New(err)
	}
	postListTemplates := map[string]*template.Template{
		"": postListTemplate,
	}
	var regenerationCount atomic.Int64
	startedAt := time.Now()

	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	if isDatabaseFS {
		type File struct {
			FilePath     string
			Text         string
			ModTime      time.Time
			CreationTime time.Time
		}
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html' ESCAPE '\\'",
				Values: []any{
					sq.StringParam("pattern", wildcardReplacer.Replace(pagesDir)+"/%"),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath:     row.String("file_path"),
					Text:         row.String("text"),
					ModTime:      row.Time("mod_time"),
					CreationTime: row.Time("creation_time"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			subgroup, subctx := errgroup.WithContext(groupctx)
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				subgroup.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					if sitePrefix != "" {
						_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
					}
					err = siteGen.GeneratePage(subctx, file.FilePath, file.Text, file.ModTime, file.CreationTime)
					if err != nil {
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			cursorA, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {postsDir})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("postsDir", postsDir),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				return err
			}
			defer cursorA.Close()
			var mutex sync.Mutex
			subgroupA, subctxA := errgroup.WithContext(groupctx)
			for cursorA.Next() {
				filePath, err := cursorA.Result()
				if err != nil {
					return err
				}
				subgroupA.Go(func() error {
					category := path.Base(filePath)
					postTemplate, err := siteGen.PostTemplate(subctxA, category)
					if err != nil {
						return err
					}
					postListTemplate, err := siteGen.PostListTemplate(subctxA, category)
					if err != nil {
						return err
					}
					mutex.Lock()
					postTemplates[category] = postTemplate
					postListTemplates[category] = postListTemplate
					mutex.Unlock()
					return nil
				})
			}
			err = cursorA.Close()
			if err != nil {
				return err
			}
			err = subgroupA.Wait()
			if err != nil {
				return err
			}
			cursorB, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.md' ESCAPE '\\'",
				Values: []any{
					sq.StringParam("pattern", wildcardReplacer.Replace(postsDir)+"/%"),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath:     row.String("file_path"),
					Text:         row.String("text"),
					ModTime:      row.Time("mod_time"),
					CreationTime: row.Time("creation_time"),
				}
			})
			if err != nil {
				return err
			}
			defer cursorB.Close()
			subgroupB, subctxB := errgroup.WithContext(groupctx)
			for cursorB.Next() {
				file, err := cursorB.Result()
				if err != nil {
					return err
				}
				subgroupB.Go(func() error {
					if sitePrefix != "" {
						_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
					}
					_, category, _ := strings.Cut(path.Dir(file.FilePath), "/")
					if category == "." {
						category = ""
					}
					postTemplate := postTemplates[category]
					if postTemplate == nil {
						return nil
					}
					err = siteGen.GeneratePost(subctxB, file.FilePath, file.Text, file.ModTime, file.CreationTime, postTemplate)
					if err != nil {
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			err = cursorB.Close()
			if err != nil {
				return err
			}
			for category, postListTemplate := range postListTemplates {
				category, postListTemplate := category, postListTemplate
				subgroupB.Go(func() error {
					n, err := siteGen.GeneratePostList(subctxB, category, postListTemplate)
					if err != nil {
						return err
					}
					regenerationCount.Add(int64(n))
					return nil
				})
			}
			err = subgroupB.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			if errors.As(err, &regenerationStats.TemplateError) {
				return regenerationStats, nil
			}
		}
	} else {
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			subgroup, subctx := errgroup.WithContext(groupctx)
			err = fs.WalkDir(nbrew.FS.WithContext(groupctx), pagesDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if filePath == pagesDir {
					return nil
				}
				subgroup.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					file, err := nbrew.FS.WithContext(subctx).Open(filePath)
					if err != nil {
						return err
					}
					fileInfo, err := file.Stat()
					if err != nil {
						return err
					}
					if fileInfo.IsDir() || !strings.HasSuffix(filePath, ".html") {
						return nil
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						return err
					}
					if sitePrefix != "" {
						_, filePath, _ = strings.Cut(filePath, "/")
					}
					var absolutePath string
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						var directoryFS *DirectoryFS
						if v.As(&directoryFS) {
							absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
						}
					}
					creationTime := CreationTime(absolutePath, fileInfo)
					err = siteGen.GeneratePage(subctx, filePath, b.String(), fileInfo.ModTime(), creationTime)
					if err != nil {
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
				return nil
			})
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			if err != nil {
				return err
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			dirEntries, err := nbrew.FS.WithContext(groupctx).ReadDir(postsDir)
			if err != nil {
				return err
			}
			var mutex sync.Mutex
			subgroupA, subctxA := errgroup.WithContext(groupctx)
			for _, dirEntry := range dirEntries {
				if !dirEntry.IsDir() {
					continue
				}
				category := dirEntry.Name()
				subgroupA.Go(func() error {
					postTemplate, err := siteGen.PostTemplate(subctxA, category)
					if err != nil {
						return err
					}
					postListTemplate, err := siteGen.PostListTemplate(subctxA, category)
					if err != nil {
						return err
					}
					mutex.Lock()
					postTemplates[category] = postTemplate
					postListTemplates[category] = postListTemplate
					mutex.Unlock()
					return nil
				})
			}
			err = subgroupA.Wait()
			if err != nil {
				return err
			}
			subgroupB, subctxB := errgroup.WithContext(groupctx)
			err = fs.WalkDir(nbrew.FS.WithContext(groupctx), postsDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if sitePrefix != "" {
					_, filePath, _ = strings.Cut(filePath, "/")
				}
				if dirEntry.IsDir() {
					_, category, _ := strings.Cut(filePath, "/")
					if strings.Contains(category, "/") {
						return fs.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(filePath, ".md") {
					return nil
				}
				subgroupB.Go(func() error {
					_, category, _ := strings.Cut(path.Dir(filePath), "/")
					if category == "." {
						category = ""
					}
					postTemplate := postTemplates[category]
					if postTemplate == nil {
						return nil
					}
					file, err := nbrew.FS.WithContext(subctxB).Open(path.Join(sitePrefix, filePath))
					if err != nil {
						return err
					}
					defer file.Close()
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
					var absolutePath string
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						var directoryFS *DirectoryFS
						if v.As(&directoryFS) {
							absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
						}
					}
					creationTime := CreationTime(absolutePath, fileInfo)
					err = siteGen.GeneratePost(subctxB, filePath, b.String(), fileInfo.ModTime(), creationTime, postTemplate)
					if err != nil {
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
				return nil
			})
			for category, postListTemplate := range postListTemplates {
				category, postListTemplate := category, postListTemplate
				subgroupB.Go(func() error {
					n, err := siteGen.GeneratePostList(subctxB, category, postListTemplate)
					if err != nil {
						return err
					}
					regenerationCount.Add(int64(n))
					return nil
				})
			}
			err = subgroupB.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			if errors.As(err, &regenerationStats.TemplateError) {
				return regenerationStats, err
			}
		}
	}
	regenerationStats.Count = regenerationCount.Load()
	regenerationStats.TimeTaken = time.Since(startedAt).String()
	return regenerationStats, nil
}

var chromaStyles = map[string]bool{
	"abap": true, "algol": true, "algol_nu": true, "api": true, "arduino": true,
	"autumn": true, "average": true, "base16-snazzy": true, "borland": true, "bw": true,
	"catppuccin-frappe": true, "catppuccin-latte": true, "catppuccin-macchiato": true,
	"catppuccin-mocha": true, "colorful": true, "compat": true, "doom-one": true,
	"doom-one2": true, "dracula": true, "emacs": true, "friendly": true, "fruity": true,
	"github-dark": true, "github": true, "gruvbox-light": true, "gruvbox": true,
	"hr_high_contrast": true, "hrdark": true, "igor": true, "lovelace": true, "manni": true,
	"modus-operandi": true, "modus-vivendi": true, "monokai": true, "monokailight": true,
	"murphy": true, "native": true, "nord": true, "onedark": true, "onesenterprise": true,
	"paraiso-dark": true, "paraiso-light": true, "pastie": true, "perldoc": true,
	"pygments": true, "rainbow_dash": true, "rose-pine-dawn": true, "rose-pine-moon": true,
	"rose-pine": true, "rrt": true, "solarized-dark": true, "solarized-dark256": true,
	"solarized-light": true, "swapoff": true, "tango": true, "trac": true, "vim": true,
	"vs": true, "vulcan": true, "witchhazel": true, "xcode-dark": true, "xcode": true,
}

var timezoneOffsets = map[string]bool{
	"-12:00": true, "-11:00": true, "-10:00": true, "-09:30": true, "-09:00": true,
	"-08:00": true, "-07:00": true, "-06:00": true, "-05:00": true, "-04:00": true,
	"-03:00": true, "-02:00": true, "-01:00": true, "+00:00": true, "+01:00": true,
	"+02:00": true, "+03:00": true, "+03:30": true, "+04:00": true, "+04:30": true,
	"+05:00": true, "+05:30": true, "+05:45": true, "+06:00": true, "+06:30": true,
	"+07:00": true, "+08:00": true, "+08:45": true, "+09:00": true, "+09:30": true,
	"+10:00": true, "+10:30": true, "+11:00": true, "+12:00": true, "+12:45": true,
	"+13:00": true, "+14:00": true,
}

var languageCodes = map[string]bool{
	"aa": true, "ab": true, "af": true, "ak": true, "am": true, "an": true, "ar": true,
	"as": true, "av": true, "ay": true, "az": true, "ba": true, "be": true, "bg": true,
	"bi": true, "bm": true, "bn": true, "bo": true, "br": true, "bs": true, "ca": true,
	"ce": true, "ch": true, "co": true, "cr": true, "cs": true, "cv": true, "cy": true,
	"da": true, "de": true, "dv": true, "dz": true, "ee": true, "el": true, "en": true,
	"eo": true, "es": true, "et": true, "eu": true, "fa": true, "ff": true, "fi": true,
	"fj": true, "fo": true, "fr": true, "fy": true, "ga": true, "gd": true, "gl": true,
	"gn": true, "gu": true, "gv": true, "ha": true, "he": true, "hi": true, "ho": true,
	"hr": true, "ht": true, "hu": true, "hy": true, "hz": true, "ia": true, "id": true,
	"ie": true, "ig": true, "ii": true, "ik": true, "io": true, "is": true, "it": true,
	"iu": true, "ja": true, "jv": true, "ka": true, "kg": true, "ki": true, "kj": true,
	"kk": true, "kl": true, "km": true, "kn": true, "ko": true, "kr": true, "ks": true,
	"ku": true, "kv": true, "kw": true, "ky": true, "lb": true, "lg": true, "li": true,
	"ln": true, "lo": true, "lt": true, "lu": true, "lv": true, "mg": true, "mh": true,
	"mi": true, "mk": true, "ml": true, "mn": true, "mr": true, "ms": true, "mt": true,
	"my": true, "na": true, "nb": true, "nd": true, "ne": true, "ng": true, "nl": true,
	"nn": true, "no": true, "nr": true, "nv": true, "ny": true, "oc": true, "oj": true,
	"om": true, "or": true, "os": true, "pa": true, "pl": true, "ps": true, "pt": true,
	"qu": true, "rm": true, "rn": true, "ro": true, "ru": true, "rw": true, "sc": true,
	"sd": true, "se": true, "sg": true, "si": true, "sk": true, "sl": true, "sm": true,
	"sn": true, "so": true, "sq": true, "sr": true, "ss": true, "st": true, "su": true,
	"sv": true, "sw": true, "ta": true, "te": true, "tg": true, "th": true, "ti": true,
	"tk": true, "tl": true, "tn": true, "to": true, "tr": true, "ts": true, "tt": true,
	"tw": true, "ty": true, "ug": true, "uk": true, "ur": true, "uz": true, "ve": true,
	"vi": true, "vo": true, "wa": true, "wo": true, "xh": true, "yi": true, "yo": true,
	"za": true, "zh": true, "zu": true,
}

var languageNames = map[string]string{
	"aa": "Afar", "ab": "Abkhazian", "af": "Afrikaans", "ak": "Akan", "am": "Amharic",
	"an": "Aragonese", "ar": "Arabic", "as": "Assamese", "av": "Avaric", "ay": "Aymara",
	"az": "Azerbaijani", "ba": "Bashkir", "be": "Belarusian", "bg": "Bulgarian",
	"bi": "Bislama", "bm": "Bambara", "bn": "Bengali", "bo": "Tibetan", "br": "Breton",
	"bs": "Bosnian", "ca": "Catalan", "ce": "Chechen", "ch": "Chamorro", "co": "Corsican",
	"cr": "Cree", "cs": "Czech", "cv": "Chuvash", "cy": "Welsh", "da": "Danish",
	"de": "German", "dv": "Divehi", "dz": "Dzongkha", "ee": "Ewe", "el": "Greek",
	"en": "English", "eo": "Esperanto", "es": "Spanish", "et": "Estonian", "eu": "Basque",
	"fa": "Persian", "ff": "Fulah", "fi": "Finnish", "fj": "Fijian", "fo": "Faroese",
	"fr": "French", "fy": "Western Frisian", "ga": "Irish", "gd": "Gaelic", "gl": "Galician",
	"gn": "Guarani", "gu": "Gujarati", "gv": "Manx", "ha": "Hausa", "he": "Hebrew",
	"hi": "Hindi", "ho": "Hiri Motu", "hr": "Croatian", "ht": "Haitian", "hu": "Hungarian",
	"hy": "Armenian", "hz": "Herero", "ia": "Interlingua", "id": "Indonesian",
	"ie": "Interlingue", "ig": "Igbo", "ii": "Sichuan Yi", "ik": "Inupiaq", "io": "Ido",
	"is": "Icelandic", "it": "Italian", "iu": "Inuktitut", "ja": "Japanese", "jv": "Javanese",
	"ka": "Georgian", "kg": "Kongo", "ki": "Kikuyu", "kj": "Kuanyama", "kk": "Kazakh",
	"kl": "Kalaallisut", "km": "Central Khmer", "kn": "Kannada", "ko": "Korean", "kr": "Kanuri",
	"ks": "Kashmiri", "ku": "Kurdish", "kv": "Komi", "kw": "Cornish", "ky": "Kirghiz",
	"lb": "Luxembourgish", "lg": "Ganda", "li": "Limburgan", "ln": "Lingala", "lo": "Lao",
	"lt": "Lithuanian", "lu": "Luba-Katanga", "lv": "Latvian", "mg": "Malagasy", "mh": "Marshallese",
	"mi": "Maori", "mk": "Macedonian", "ml": "Malayalam", "mn": "Mongolian", "mr": "Marathi",
	"ms": "Malay", "mt": "Maltese", "my": "Burmese", "na": "Nauru", "nb": "Norwegian Bokmål",
	"nd": "North Ndebele", "ne": "Nepali", "ng": "Ndonga", "nl": "Dutch; Flemish",
	"nn": "Norwegian Nynorsk", "no": "Norwegian", "nr": "South Ndebele", "nv": "Navajo",
	"ny": "Chichewa", "oc": "Occitan", "oj": "Ojibwa", "om": "Oromo", "or": "Oriya", "os": "Ossetian",
	"pa": "Panjabi", "pl": "Polish", "ps": "Pushto", "pt": "Portuguese", "qu": "Quechua",
	"rm": "Romansh", "rn": "Rundi", "ro": "Romanian", "ru": "Russian", "rw": "Kinyarwanda",
	"sc": "Sardinian", "sd": "Sindhi", "se": "Northern Sami", "sg": "Sango", "si": "Sinhala",
	"sk": "Slovak", "sl": "Slovenian", "sm": "Samoan", "sn": "Shona", "so": "Somali",
	"sq": "Albanian", "sr": "Serbian", "ss": "Swati", "st": "Southern Sotho", "su": "Sundanese",
	"sv": "Swedish", "sw": "Swahili", "ta": "Tamil", "te": "Telugu", "tg": "Tajik", "th": "Thai",
	"ti": "Tigrinya", "tk": "Turkmen", "tl": "Tagalog", "tn": "Tswana", "to": "Tonga", "tr": "Turkish",
	"ts": "Tsonga", "tt": "Tatar", "tw": "Twi", "ty": "Tahitian", "ug": "Uighur", "uk": "Ukrainian",
	"ur": "Urdu", "uz": "Uzbek", "ve": "Venda", "vi": "Vietnamese", "vo": "Volapük", "wa": "Walloon",
	"wo": "Wolof", "xh": "Xhosa", "yi": "Yiddish", "yo": "Yoruba", "za": "Zhuang",
	"zh": "Chinese", "zu": "Zulu",
}
