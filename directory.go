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

func (nbrew *Notebrew) directory(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
	}
	type Response struct {
		ContentBaseURL        string            `json:"contentBaseURL"`
		CDNDomain             string            `json:"cdnDomain"`
		IsDatabaseFS          bool              `json:"isDatabaseFS"`
		SitePrefix            string            `json:"sitePrefix"`
		UserID                ID                `json:"userID"`
		Username              string            `json:"username"`
		TimezoneOffsetSeconds int               `json:"timezoneOffsetSeconds"`
		DisableReason         string            `json:"disableReason"`
		FileID                ID                `json:"fileID"`
		FilePath              string            `json:"filePath"`
		IsDir                 bool              `json:"isDir"`
		ModTime               time.Time         `json:"modTime"`
		CreationTime          time.Time         `json:"creationTime"`
		UploadableExts        []string          `json:"uploadableExts"`
		PinnedFiles           []File            `json:"pinnedFiles"`
		Files                 []File            `json:"files"`
		Sort                  string            `json:"sort"`
		Order                 string            `json:"order"`
		From                  string            `json:"from"`
		FromEdited            string            `json:"fromEdited"`
		FromCreated           string            `json:"fromCreated"`
		FromSize              string            `json:"fromSize"`
		Before                string            `json:"before"`
		BeforeEdited          string            `json:"beforeEdited"`
		BeforeCreated         string            `json:"beforeCreated"`
		BeforeSize            string            `json:"beforeSize"`
		Limit                 int               `json:"limit"`
		PreviousURL           string            `json:"previousURL"`
		NextURL               string            `json:"nextURL"`
		RegenerationStats     RegenerationStats `json:"regenerationStats"`
		PostRedirectGet       map[string]any    `json:"postRedirectGet"`
	}
	const dateFormat = "2006-01-02"
	const timeFormat = "2006-01-02T150405.999999999-0700"
	const zuluTimeFormat = "2006-01-02T150405.999999999Z"
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if response.PinnedFiles == nil {
			response.PinnedFiles = []File{}
		}
		if response.Files == nil {
			response.Files = []File{}
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
			if err == nil {
				sourceSitePrefix := values.Get("sitePrefix")
				if sourceSitePrefix == sitePrefix {
					if values.Has("cut") {
						clipboard.Set("cut", "")
					}
					clipboard.Set("sitePrefix", sourceSitePrefix)
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
		}
		isSeeking := response.From != "" || response.FromEdited != "" || response.FromCreated != "" ||
			response.Before != "" || response.BeforeEdited != "" || response.BeforeCreated != ""
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
			"float64ToInt64":        func(n float64) int64 { return int64(n) },
			"formatTime": func(t time.Time, layout string, offset int) string {
				return t.In(time.FixedZone("", offset)).Format(layout)
			},
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"getFileType": func(name string) FileType {
				return AllowedFileTypes[strings.ToLower(path.Ext(name))]
			},
			"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
				var b strings.Builder
				b.WriteString("<a href='/files/'>files</a>")
				segments := strings.Split(filePath, "/")
				if sitePrefix != "" {
					segments = append([]string{sitePrefix}, segments...)
				}
				for i := 0; i < len(segments); i++ {
					if segments[i] == "" {
						continue
					}
					href := "/files/" + path.Join(segments[:i+1]...) + "/"
					b.WriteString(" / <a href='" + template.HTMLEscapeString(href) + "'>" + template.HTMLEscapeString(segments[i]) + "</a>")
				}
				b.WriteString(" /")
				return template.HTML(b.String())
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.FilePath != clipboard.Get("parent") {
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
			"sortBy": func(sort string) template.URL {
				queryParams := "?persist" +
					"&sort=" + url.QueryEscape(sort) +
					"&order=" + url.QueryEscape(response.Order) +
					"&limit=" + strconv.Itoa(response.Limit)
				if isSeeking && response.IsDatabaseFS && len(response.Files) > 0 {
					firstFile := response.Files[0]
					queryParams += "&from=" + url.QueryEscape(firstFile.Name) +
						"&fromEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(firstFile.Size, 10)
				}
				return template.URL(queryParams)
			},
			"orderBy": func(order string) template.URL {
				queryParams := "?persist" +
					"&sort=" + url.QueryEscape(response.Sort) +
					"&order=" + url.QueryEscape(order) +
					"&limit=" + strconv.Itoa(response.Limit)
				if isSeeking && response.IsDatabaseFS && len(response.Files) > 0 {
					firstFile := response.Files[0]
					queryParams += "&from=" + url.QueryEscape(firstFile.Name) +
						"&fromEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(firstFile.Size, 10)
				}
				return template.URL(queryParams)
			},
			"limitTo": func(limit int) template.URL {
				var b strings.Builder
				b.WriteString("?persist")
				b.WriteString("&sort=" + url.QueryEscape(response.Sort))
				b.WriteString("&order=" + url.QueryEscape(response.Order))
				b.WriteString("&limit=" + strconv.Itoa(limit))
				if response.From != "" {
					b.WriteString("&from=" + url.QueryEscape(response.From))
				}
				if response.FromEdited != "" {
					b.WriteString("&fromEdited=" + url.QueryEscape(response.FromEdited))
				}
				if response.FromCreated != "" {
					b.WriteString("&fromCreated=" + url.QueryEscape(response.FromCreated))
				}
				if response.FromSize != "" {
					b.WriteString("&fromSize=" + url.QueryEscape(response.FromSize))
				}
				if response.Before != "" {
					b.WriteString("&before=" + url.QueryEscape(response.Before))
				}
				if response.BeforeEdited != "" {
					b.WriteString("&beforeEdited=" + url.QueryEscape(response.BeforeEdited))
				}
				if response.BeforeCreated != "" {
					b.WriteString("&beforeCreated=" + url.QueryEscape(response.BeforeCreated))
				}
				if response.BeforeSize != "" {
					b.WriteString("&beforeSize=" + url.QueryEscape(response.BeforeSize))
				}
				return template.URL(b.String())
			},
		}
		tmpl, err := template.New("directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/directory.html")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.ExecuteTemplate(w, r, tmpl, &response)
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.MethodNotAllowed(w, r)
		return
	}

	head, _, _ := strings.Cut(filePath, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		nbrew.NotFound(w, r)
		return
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
	response.SitePrefix = sitePrefix
	response.UserID = user.UserID
	response.Username = user.Username
	response.TimezoneOffsetSeconds = user.TimezoneOffsetSeconds
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
	response.IsDir = true
	var sortCookie, orderCookie, limitCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		switch cookie.Name {
		case "sort":
			sortCookie = cookie
		case "order":
			orderCookie = cookie
		case "limit":
			limitCookie = cookie
		}
	}
	response.Sort = strings.ToLower(strings.TrimSpace(r.Form.Get("sort")))
	if response.Sort == "" && sortCookie != nil {
		response.Sort = sortCookie.Value
	}
	switch response.Sort {
	case "name", "edited", "created", "size":
		break
	default:
		if head == "notes" {
			response.Sort = "edited"
		} else if head == "posts" {
			response.Sort = "created"
		} else {
			response.Sort = "name"
		}
	}
	response.Order = strings.ToLower(strings.TrimSpace(r.Form.Get("order")))
	if response.Order == "" && orderCookie != nil {
		response.Order = orderCookie.Value
	}
	switch response.Order {
	case "asc", "desc":
		break
	default:
		if response.Sort == "created" || response.Sort == "edited" {
			response.Order = "desc"
		} else {
			response.Order = "asc"
		}
	}
	response.Limit, _ = strconv.Atoi(r.Form.Get("limit"))
	if response.Limit == 0 && limitCookie != nil {
		response.Limit, _ = strconv.Atoi(limitCookie.Value)
	}
	if response.Limit <= 0 {
		response.Limit = 200
	}
	if r.Form.Has("persist") {
		if r.Form.Has("sort") {
			isDefaultSort := false
			if head == "notes" {
				isDefaultSort = response.Sort == "edited"
			} else if head == "posts" {
				isDefaultSort = response.Sort == "created"
			} else {
				isDefaultSort = response.Sort == "name"
			}
			if isDefaultSort {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "sort",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "sort",
					Value:    response.Sort,
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		if r.Form.Has("order") {
			isDefaultOrder := false
			if response.Sort == "created" || response.Sort == "edited" {
				isDefaultOrder = response.Order == "desc"
			} else {
				isDefaultOrder = response.Order == "asc"
			}
			if isDefaultOrder {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "order",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "order",
					Value:    response.Order,
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		if r.Form.Has("limit") {
			if response.Limit == 0 || response.Limit == 200 {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "limit",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "limit",
					Value:    strconv.Itoa(response.Limit),
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
	}
	switch head {
	case "pages":
		response.UploadableExts = []string{".html"}
	case "posts":
		response.UploadableExts = []string{".md"}
	default:
		response.UploadableExts = make([]string, 0, len(editableExts)+len(imgExts)+len(videoExts)+len(fontExts))
		response.UploadableExts = append(response.UploadableExts, editableExts...)
		if !user.UserFlags["NoUploadImage"] {
			response.UploadableExts = append(response.UploadableExts, imgExts...)
		}
		if !user.UserFlags["NoUploadVideo"] {
			response.UploadableExts = append(response.UploadableExts, videoExts...)
		}
		response.UploadableExts = append(response.UploadableExts, fontExts...)
	}

	databaseFS, ok := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if !ok {
		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(path.Join(sitePrefix, filePath))
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.Files = make([]File, 0, len(dirEntries))
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			name := fileInfo.Name()
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath, name)
				}
			}
			file := File{
				Parent:       filePath,
				Name:         name,
				IsDir:        fileInfo.IsDir(),
				Size:         fileInfo.Size(),
				ModTime:      fileInfo.ModTime(),
				CreationTime: CreationTime(absolutePath, fileInfo),
			}
			if file.IsDir {
				response.Files = append(response.Files, file)
				continue
			}
			_, ok := AllowedFileTypes[strings.ToLower(path.Ext(file.Name))]
			if !ok {
				continue
			}
			response.Files = append(response.Files, file)
		}
		switch response.Sort {
		case "name":
			if response.Order == "desc" {
				slices.Reverse(response.Files)
			}
		case "edited":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.ModTime.Equal(b.ModTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.ModTime.Before(b.ModTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		case "created":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.CreationTime.Equal(b.CreationTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.CreationTime.Before(b.CreationTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		case "size":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.CreationTime.Equal(b.CreationTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.CreationTime.Before(b.CreationTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		}
		writeResponse(w, r, response)
		return
	}

	var fromEdited, beforeEdited, fromCreated, beforeCreated time.Time
	var fromSize, beforeSize int64
	response.From = r.Form.Get("from")
	response.Before = r.Form.Get("before")
	_, _ = fromSize, beforeSize
	if s := r.Form.Get("fromEdited"); s != "" {
		if len(s) == len(dateFormat) {
			fromEdited, err = time.ParseInLocation(dateFormat, s, time.FixedZone("", user.TimezoneOffsetSeconds))
			if err == nil {
				response.FromEdited = fromEdited.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			fromEdited, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.FromEdited = fromEdited.Format(zuluTimeFormat)
			}
		} else {
			fromEdited, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.FromEdited = fromEdited.Format(timeFormat)
			}
		}
	}
	if s := r.Form.Get("beforeEdited"); s != "" {
		if len(s) == len(dateFormat) {
			beforeEdited, err = time.ParseInLocation(dateFormat, s, time.FixedZone("", user.TimezoneOffsetSeconds))
			if err == nil {
				response.BeforeEdited = beforeEdited.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			beforeEdited, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.BeforeEdited = beforeEdited.Format(zuluTimeFormat)
			}
		} else {
			beforeEdited, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.BeforeEdited = beforeEdited.Format(timeFormat)
			}
		}
	}
	if s := r.Form.Get("fromCreated"); s != "" {
		if len(s) == len(dateFormat) {
			fromCreated, err = time.ParseInLocation(dateFormat, s, time.FixedZone("", user.TimezoneOffsetSeconds))
			if err == nil {
				response.FromCreated = fromCreated.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			fromCreated, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.FromCreated = fromCreated.Format(zuluTimeFormat)
			}
		} else {
			fromCreated, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.FromCreated = fromCreated.Format(timeFormat)
			}
		}
	}
	if s := r.Form.Get("beforeCreated"); s != "" {
		if len(s) == len(dateFormat) {
			beforeCreated, err = time.ParseInLocation(dateFormat, s, time.FixedZone("", user.TimezoneOffsetSeconds))
			if err == nil {
				response.BeforeCreated = beforeCreated.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			beforeCreated, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.BeforeCreated = beforeCreated.Format(zuluTimeFormat)
			}
		} else {
			beforeCreated, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.BeforeCreated = beforeCreated.Format(timeFormat)
			}
		}
	}
	if s := r.Form.Get("fromSize"); s != "" {
		fromSize, err = strconv.ParseInt(s, 10, 64)
		if err == nil {
			response.FromSize = strconv.FormatInt(fromSize, 10)
		}
	}
	if s := r.Form.Get("beforeSize"); s != "" {
		beforeSize, err = strconv.ParseInt(s, 10, 64)
		if err == nil {
			response.BeforeSize = strconv.FormatInt(beforeSize, 10)
		}
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// waitFiles unblocks when it is safe to read from response.Files.
	//
	// This is only used within an errgroup goroutine -- once all errgroup
	// goroutines have completed, it is always safe to read from response.Files.
	waitFiles := make(chan struct{})
	group, groupctx := errgroup.WithContext(r.Context())
	group.Go(func() (err error) {
		defer stacktrace.RecoverPanic(&err)
		pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM pinned_file" +
				" JOIN files ON files.file_id = pinned_file.file_id" +
				" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" ORDER BY files.file_path",
			Values: []any{
				sq.StringParam("parent", path.Join(sitePrefix, filePath)),
			},
		}, func(row *sq.Row) File {
			filePath := row.String("files.file_path")
			return File{
				FileID:       row.UUID("files.file_id"),
				Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
				Name:         path.Base(filePath),
				Size:         row.Int64("files.size"),
				ModTime:      row.Time("files.mod_time"),
				CreationTime: row.Time("files.creation_time"),
				IsDir:        row.Bool("files.is_dir"),
			}
		})
		if err != nil {
			return stacktrace.New(err)
		}
		response.PinnedFiles = pinnedFiles
		return nil
	})
	switch response.Sort {
	case "name":
		if response.From != "" && response.Before != "" {
			//-------------------------------//
			// Read everything between names //
			//-------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path >= {from} AND file_path < {before}",
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("file_path ASC")
				} else {
					condition = sq.Expr("file_path > {before} AND file_path <= {from}",
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path < {from}", sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)))
					order = sq.Expr("file_path DESC")
				} else {
					condition = sq.Expr("file_path > {from}", sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)))
					order = sq.Expr("file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path >= {before}", sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)))
					order = sq.Expr("file_path ASC")
				} else {
					condition = sq.Expr("file_path <= {before}", sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)))
					order = sq.Expr("file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else if response.From != "" {
			//----------------------------//
			// Read everything after name //
			//----------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path >= {from}", sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)))
					order = sq.Expr("file_path ASC")
				} else {
					condition = sq.Expr("file_path <= {from}", sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)))
					order = sq.Expr("file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path < {from}", sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)))
					order = sq.Expr("file_path DESC")
				} else {
					condition = sq.Expr("file_path > {from}", sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)))
					order = sq.Expr("file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
		} else if response.Before != "" {
			//-----------------------------//
			// Read everything before name //
			//-----------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path < {before}", sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)))
					order = sq.Expr("file_path DESC")
				} else {
					condition = sq.Expr("file_path > {before}", sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)))
					order = sq.Expr("file_path ASC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[:response.Limit]
					slices.Reverse(response.Files)
					firstFile := response.Files[0]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&before=" + url.QueryEscape(firstFile.Name) +
							"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
					}
					response.PreviousURL = uri.String()
				} else {
					slices.Reverse(response.Files)
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("file_path >= {before}", sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)))
					order = sq.Expr("file_path ASC")
				} else {
					condition = sq.Expr("file_path <= {before}", sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)))
					order = sq.Expr("file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else {
			//-----------------------------//
			// Read from the start by name //
			//-----------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var order sq.Expression
				if response.Order == "asc" {
					order = sq.Expr("file_path ASC")
				} else {
					order = sq.Expr("file_path DESC")
				}
				files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
		}
	case "edited":
		if response.FromEdited != "" && response.BeforeEdited != "" {
			//--------------------------------------------//
			// Read everything between modification times //
			//--------------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) >= ({fromEdited}, {from}) AND (mod_time, file_path) < ({beforeEdited}, {before})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(mod_time, file_path) > ({beforeEdited}, {before}) AND (mod_time, file_path) <= ({fromEdited}, {from})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) < ({fromEdited}, {from})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				} else {
					condition = sq.Expr("(mod_time, file_path) > ({fromEdited}, {from})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) >= ({beforeEdited}, {before})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(mod_time, file_path) <= ({beforeEdited}, {before})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else if response.FromEdited != "" {
			//-----------------------------------------//
			// Read everything after modification time //
			//-----------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) >= ({fromEdited}, {from})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(mod_time, file_path) <= ({fromEdited}, {from})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) < ({fromEdited}, {from})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				} else {
					condition = sq.Expr("(mod_time, file_path) > ({fromEdited}, {from})",
						sq.TimeParam("fromEdited", fromEdited),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
		} else if response.BeforeEdited != "" {
			//------------------------------------------//
			// Read everything before modification time //
			//------------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) < ({beforeEdited}, {before})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				} else {
					condition = sq.Expr("(mod_time, file_path) > ({beforeEdited}, {before})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[:response.Limit]
					slices.Reverse(response.Files)
					firstFile := response.Files[0]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&before=" + url.QueryEscape(firstFile.Name) +
							"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
					}
					response.PreviousURL = uri.String()
				} else {
					slices.Reverse(response.Files)
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(mod_time, file_path) >= ({beforeEdited}, {before})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(mod_time, file_path) <= ({beforeEdited}, {before})",
						sq.TimeParam("beforeEdited", beforeEdited),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("mod_time DESC, file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else {
			//------------------------------------------//
			// Read from the start by modification time //
			//------------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var order sq.Expression
				if response.Order == "asc" {
					order = sq.Expr("mod_time ASC, file_path ASC")
				} else {
					order = sq.Expr("mod_time DESC, file_path DESC")
				}
				files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
		}
	case "created":
		if response.FromCreated != "" && response.BeforeCreated != "" {
			//----------------------------------------//
			// Read everything between creation times //
			//----------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) >= ({fromCreated}, {from}) AND (creation_time, file_path) < ({beforeCreated}, {before})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(creation_time, file_path) > ({beforeCreated}, {before}) AND (creation_time, file_path) <= ({fromCreated}, {from})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) < ({fromCreated}, {from})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				} else {
					condition = sq.Expr("(creation_time, file_path) > ({fromCreated}, {from})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) >= ({beforeCreated}, {before})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(creation_time, file_path) <= ({beforeCreated}, {before})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else if response.FromCreated != "" {
			//-------------------------------------//
			// Read everything after creation time //
			//-------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) >= ({fromCreated}, {from})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(creation_time, file_path) <= ({fromCreated}, {from})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) < ({fromCreated}, {from})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				} else {
					condition = sq.Expr("(creation_time, file_path) > ({fromCreated}, {from})",
						sq.TimeParam("fromCreated", fromCreated),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
		} else if response.BeforeCreated != "" {
			//--------------------------------------//
			// Read everything before creation time //
			//--------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) < ({beforeCreated}, {before})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				} else {
					condition = sq.Expr("(creation_time, file_path) > ({beforeCreated}, {before})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[:response.Limit]
					slices.Reverse(response.Files)
					firstFile := response.Files[0]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&before=" + url.QueryEscape(firstFile.Name) +
							"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
					}
					response.PreviousURL = uri.String()
				} else {
					slices.Reverse(response.Files)
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(creation_time, file_path) >= ({beforeCreated}, {before})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time ASC, file_path ASC")
				} else {
					condition = sq.Expr("(creation_time, file_path) <= ({beforeCreated}, {before})",
						sq.TimeParam("beforeCreated", beforeCreated),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("creation_time DESC, file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else {
			//--------------------------------------//
			// Read from the start by creation time //
			//--------------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var order sq.Expression
				if response.Order == "asc" {
					order = sq.Expr("creation_time ASC, file_path ASC")
				} else {
					order = sq.Expr("creation_time DESC, file_path DESC")
				}
				files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
		}
	case "size":
		if response.FromSize != "" && response.BeforeSize != "" {
			//-------------------------------//
			// Read everything between sizes //
			//-------------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) >= ({fromSize}, {from}) AND (size, file_path) < ({beforeSize}, {before})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				} else {
					condition = sq.Expr("(size, file_path) > ({beforeSize}, {before}) AND (size, file_path) <= ({fromSize}, {from})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) < ({fromSize}, {from})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				} else {
					condition = sq.Expr("(size, file_path) > ({fromSize}, {from})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) >= ({beforeSize}, {before})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				} else {
					condition = sq.Expr("(size, file_path) <= ({beforeSize}, {before})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else if response.FromSize != "" {
			//----------------------------//
			// Read everything after size //
			//----------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) >= ({fromSize}, {from})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				} else {
					condition = sq.Expr("(size, file_path) <= ({fromSize}, {from})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) < ({fromSize}, {from})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				} else {
					condition = sq.Expr("(size, file_path) > ({fromSize}, {from})",
						sq.Int64Param("fromSize", fromSize),
						sq.StringParam("from", path.Join(sitePrefix, filePath, response.From)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return stacktrace.New(err)
				}
				if hasPreviousFile {
					<-waitFiles
					if len(response.Files) > 0 {
						firstFile := response.Files[0]
						uri := &url.URL{
							Scheme: scheme,
							Host:   r.Host,
							Path:   r.URL.Path,
							RawQuery: "sort=" + url.QueryEscape(response.Sort) +
								"&order=" + url.QueryEscape(response.Order) +
								"&limit=" + strconv.Itoa(response.Limit) +
								"&before=" + url.QueryEscape(firstFile.Name) +
								"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
								"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
								"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
						}
						response.PreviousURL = uri.String()
					}
				}
				return nil
			})
		} else if response.BeforeSize != "" {
			//-----------------------------//
			// Read everything before size //
			//-----------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer close(waitFiles)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) < ({beforeSize}, {before})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				} else {
					condition = sq.Expr("(size, file_path) > ({beforeSize}, {before})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[:response.Limit]
					slices.Reverse(response.Files)
					firstFile := response.Files[0]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&before=" + url.QueryEscape(firstFile.Name) +
							"&beforeEdited=" + url.QueryEscape(firstFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&beforeCreated=" + url.QueryEscape(firstFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&beforeSize=" + strconv.FormatInt(firstFile.Size, 10),
					}
					response.PreviousURL = uri.String()
				} else {
					slices.Reverse(response.Files)
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var condition, order sq.Expression
				if response.Order == "asc" {
					condition = sq.Expr("(size, file_path) >= ({beforeSize}, {before})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size ASC, file_path ASC")
				} else {
					condition = sq.Expr("(size, file_path) <= ({beforeSize}, {before})",
						sq.Int64Param("beforeSize", beforeSize),
						sq.StringParam("before", path.Join(sitePrefix, filePath, response.Before)),
					)
					order = sq.Expr("size DESC, file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND {condition}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("condition", condition),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						Size:         row.Int64("size"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&limit=" + strconv.Itoa(response.Limit) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
						"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
						"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
				}
				response.NextURL = uri.String()
				return nil
			})
		} else {
			//-----------------------------//
			// Read from the start by size //
			//-----------------------------//
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var order sq.Expression
				if response.Order == "asc" {
					order = sq.Expr("size ASC, file_path ASC")
				} else {
					order = sq.Expr("size DESC, file_path DESC")
				}
				files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, filePath)),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return stacktrace.New(err)
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&limit=" + strconv.Itoa(response.Limit) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&fromEdited=" + url.QueryEscape(nextFile.ModTime.UTC().Format(zuluTimeFormat)) +
							"&fromCreated=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(zuluTimeFormat)) +
							"&fromSize=" + strconv.FormatInt(nextFile.Size, 10),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
		}
	}
	err = group.Wait()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	writeResponse(w, r, response)
}
