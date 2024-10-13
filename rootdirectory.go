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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) rootdirectory(w http.ResponseWriter, r *http.Request, user User, sitePrefix string, modTime time.Time) {
	type File struct {
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
	}
	type Site struct {
		Name  string `json:"name"`
		Owner string `json:"owner"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		SiteCount         int64             `json:"siteCount"`
		DisableReason     string            `json:"disableReason"`
		SiteLimit         int64             `json:"siteLimit"`
		FilePath          string            `json:"filePath"`
		IsDir             bool              `json:"isDir"`
		Files             []File            `json:"files"`
		Sites             []Site            `json:"sites"`
		From              string            `json:"from"`
		Before            string            `json:"before"`
		Limit             int               `json:"limit"`
		PreviousURL       string            `json:"previousURL"`
		NextURL           string            `json:"nextURL"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if response.Sites == nil {
			response.Sites = []Site{}
		}
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
		}
		tmpl, err := template.New("rootdirectory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/rootdirectory.html")
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
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		response.IsDatabaseFS = v.As(&DatabaseFS{})
	}
	response.UserID = user.UserID
	response.Username = user.Username
	response.DisableReason = user.DisableReason
	response.SiteLimit = user.SiteLimit
	response.IsDir = true
	if sitePrefix == "" && nbrew.DB != nil {
		sites, err := sq.FetchAll(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "SELECT {*}" +
				" FROM site_user" +
				" JOIN site ON site.site_id = site_user.site_id" +
				" JOIN users ON users.user_id = site_user.user_id" +
				" LEFT JOIN site_owner ON site_owner.site_id = site_user.site_id" +
				" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
				" WHERE users.username = {username}" +
				" ORDER BY site_prefix",
			Values: []any{
				sq.StringParam("username", user.Username),
			},
		}, func(row *sq.Row) Site {
			return Site{
				Name: row.String("CASE"+
					" WHEN site.site_name LIKE '%.%' ESCAPE '\\' THEN site.site_name"+
					" WHEN site.site_name <> '' THEN {}"+
					" ELSE ''"+
					" END AS site_prefix",
					sq.DialectExpression{
						Default: sq.Expr("'@' || site.site_name"),
						Cases: []sq.DialectCase{{
							Dialect: "mysql",
							Result:  sq.Expr("concat('@', site.site_name)"),
						}},
					},
				),
				Owner: row.String("owner.username"),
			}
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.Sites = sites
		authorizedForDefaultSite := false
		n := slices.IndexFunc(response.Sites, func(site Site) bool { return site.Name == "" })
		if n >= 0 {
			authorizedForDefaultSite = true
			copy(response.Sites[n:], response.Sites[n+1:])
			response.Sites = response.Sites[:len(response.Sites)-1]
		}
		for _, site := range response.Sites {
			if site.Owner == user.Username {
				response.SiteCount++
			}
		}
		if !authorizedForDefaultSite {
			writeResponse(w, r, response)
			return
		}
	}

	databaseFS, ok := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if !ok {
		for _, name := range []string{"notes", "pages", "posts", "output/themes", "output", "site.json", "imports", "exports"} {
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, name))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, sitePrefix, name)
				}
			}
			response.Files = append(response.Files, File{
				Name:         name,
				IsDir:        fileInfo.IsDir(),
				ModTime:      fileInfo.ModTime(),
				CreationTime: CreationTime(absolutePath, fileInfo),
			})
		}

		if sitePrefix != "" || nbrew.DB != nil {
			writeResponse(w, r, response)
			return
		}

		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(".")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		for _, dirEntry := range dirEntries {
			if !dirEntry.IsDir() {
				continue
			}
			name := dirEntry.Name()
			if strings.HasPrefix(name, "@") || strings.Contains(name, ".") {
				response.Sites = append(response.Sites, Site{Name: name})
			}
		}
		writeResponse(w, r, response)
		return
	}

	files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE file_path IN ({notes}, {pages}, {posts}, {themes}, {output}, {imports}, {exports}, {sitejson})" +
			" ORDER BY CASE file_path" +
			" WHEN {notes} THEN 1" +
			" WHEN {pages} THEN 2" +
			" WHEN {posts} THEN 3" +
			" WHEN {themes} THEN 4" +
			" WHEN {output} THEN 5" +
			" WHEN {sitejson} THEN 6" +
			" WHEN {imports} THEN 7" +
			" WHEN {exports} THEN 8" +
			" END",
		Values: []any{
			sq.StringParam("notes", path.Join(sitePrefix, "notes")),
			sq.StringParam("pages", path.Join(sitePrefix, "pages")),
			sq.StringParam("posts", path.Join(sitePrefix, "posts")),
			sq.StringParam("themes", path.Join(sitePrefix, "output/themes")),
			sq.StringParam("sitejson", path.Join(sitePrefix, "site.json")),
			sq.StringParam("output", path.Join(sitePrefix, "output")),
			sq.StringParam("imports", path.Join(sitePrefix, "imports")),
			sq.StringParam("exports", path.Join(sitePrefix, "exports")),
		},
	}, func(row *sq.Row) File {
		return File{
			Name:         strings.Trim(strings.TrimPrefix(row.String("file_path"), sitePrefix), "/"),
			ModTime:      row.Time("mod_time"),
			CreationTime: row.Time("creation_time"),
			IsDir:        row.Bool("is_dir"),
		}
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	response.Files = files

	if sitePrefix != "" || nbrew.DB != nil {
		writeResponse(w, r, response)
		return
	}

	response.Limit, _ = strconv.Atoi(r.Form.Get("limit"))
	if response.Limit <= 0 {
		response.Limit = 1000
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	response.From = r.Form.Get("from")
	if response.From != "" {
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			sites, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' ESCAPE '\\' OR file_path LIKE '%.%' ESCAPE '\\')" +
					" AND file_path >= {from}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("from", response.From),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) Site {
				return Site{
					Name: row.String("files.file_path"),
				}
			})
			if err != nil {
				return stacktrace.New(err)
			}
			response.Sites = sites
			if len(response.Sites) > response.Limit {
				uri := &url.URL{
					Scheme:   scheme,
					Host:     r.Host,
					Path:     r.URL.Path,
					RawQuery: "from=" + url.QueryEscape(response.Sites[response.Limit].Name) + "&limit=" + strconv.Itoa(response.Limit),
				}
				response.Sites = response.Sites[:response.Limit]
				response.NextURL = uri.String()
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			hasPreviousSite, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT 1" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' ESCAPE '\\' OR file_path LIKE '%.%')" +
					" AND file_path < {from}",
				Values: []any{
					sq.StringParam("from", response.From),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
			if hasPreviousSite {
				uri := &url.URL{
					Scheme:   scheme,
					Host:     r.Host,
					Path:     r.URL.Path,
					RawQuery: "before=" + url.QueryEscape(response.From) + "&limit=" + strconv.Itoa(response.Limit),
				}
				response.PreviousURL = uri.String()
			}
			return nil
		})
		err := group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	response.Before = r.Form.Get("before")
	if response.Before != "" {
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			response.Sites, err = sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' ESCAPE '\\' OR file_path LIKE '%.%' ESCAPE '\\')" +
					" AND file_path < {before}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("before", response.Before),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) Site {
				return Site{
					Name: row.String("files.file_path"),
				}
			})
			if err != nil {
				return stacktrace.New(err)
			}
			if len(response.Sites) > response.Limit {
				response.Sites = response.Sites[1:]
				uri := &url.URL{
					Scheme:   scheme,
					Host:     r.Host,
					Path:     r.URL.Path,
					RawQuery: "before=" + url.QueryEscape(response.Sites[0].Name) + "&limit=" + strconv.Itoa(response.Limit),
				}
				response.PreviousURL = uri.String()
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			nextSite, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND file_path >= {before}" +
					" ORDER BY file_path" +
					" LIMIT 1",
				Values: []any{
					sq.StringParam("before", response.Before),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return stacktrace.New(err)
			}
			uri := &url.URL{
				Scheme:   scheme,
				Host:     r.Host,
				Path:     r.URL.Path,
				RawQuery: "from=" + url.QueryEscape(nextSite) + "&limit=" + strconv.Itoa(response.Limit),
			}
			response.NextURL = uri.String()
			return nil
		})
		err := group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	sites, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE parent_id IS NULL" +
			" AND is_dir" +
			" AND (file_path LIKE '@%' ESCAPE '\\' OR file_path LIKE '%.%' ESCAPE '\\')" +
			" ORDER BY file_path" +
			" LIMIT {limit} + 1",
		Values: []any{
			sq.IntParam("limit", response.Limit),
		},
	}, func(row *sq.Row) Site {
		return Site{
			Name: row.String("files.file_path"),
		}
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	response.Sites = sites
	if len(response.Sites) > response.Limit {
		uri := &url.URL{
			Scheme:   scheme,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: "from=" + url.QueryEscape(response.Sites[response.Limit].Name) + "&limit=" + strconv.Itoa(response.Limit),
		}
		response.Sites = response.Sites[:response.Limit]
		response.NextURL = uri.String()
	}
	writeResponse(w, r, response)
	return
}
