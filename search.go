package notebrew

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/bokwoon95/notebrew/sq"
)

var quoteReplacer = strings.NewReplacer(`"`, ``, `“`, ``, `”`, ``, `„`, ``, `‟`, ``)

func (nbrew *Notebrew) search(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Match struct {
		FileID       ID        `json:"fileID"`
		FilePath     string    `json:"filePath"`
		IsDir        bool      `json:"isDir"`
		Preview      string    `json:"preview"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Request struct {
		Parent         string   `json:"parent"`
		MustInclude    string   `json:"mustInclude"`
		MayInclude     string   `json:"mayInclude"`
		Exclude        string   `json:"exclude"`
		MandatoryTerms []string `json:"mandatoryTerms"`
		OptionalTerms  []string `json:"optionalTerms"`
		ExcludeTerms   []string `json:"excludeTerms"`
		FileTypes      []string `json:"fileTypes"`
	}
	type Response struct {
		ContentBaseURL     string   `json:"contentBaseURL"`
		SitePrefix         string   `json:"sitePrefix"`
		CDNDomain          string   `json:"cdnDomain"`
		IsDatabaseFS       bool     `json:"isDatabaseFS"`
		UserID             ID       `json:"userID"`
		Username           string   `json:"username"`
		DisableReason      string   `json:"disableReason"`
		Parent             string   `json:"parent"`
		MandatoryTerms     []string `json:"mandatoryTerms"`
		OptionalTerms      []string `json:"optionalTerms"`
		ExcludeTerms       []string `json:"excludeTerms"`
		FileTypes          []string `json:"fileTypes"`
		AvailableFileTypes []string `json:"availableFileTypes"`
		Matches            []Match  `json:"matches"`
	}

	if r.Method != "GET" {
		nbrew.MethodNotAllowed(w, r)
		return
	}

	databaseFS, ok := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case *DatabaseFS:
		databaseFS, ok = v, true
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if !ok {
		nbrew.NotFound(w, r)
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
		referer := nbrew.GetReferer(r)
		selectedFileTypes := make(map[string]struct{})
		for _, value := range response.FileTypes {
			selectedFileTypes[value] = struct{}{}
		}
		funcMap := map[string]any{
			"join":       path.Join,
			"dir":        path.Dir,
			"base":       path.Base,
			"ext":        path.Ext,
			"hasPrefix":  strings.HasPrefix,
			"trimPrefix": strings.TrimPrefix,
			"contains":   strings.Contains,
			"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS": func() template.JS { return template.JS(BaselineJS) },
			"referer":    func() string { return referer },
			"incr":       func(n int) int { return n + 1 },
			"fileTypeSelected": func(value string) bool {
				_, ok := selectedFileTypes[value]
				return ok
			},
			"getFileType": func(name string) FileType {
				return AllowedFileTypes[strings.ToLower(path.Ext(name))]
			},
			"joinTerms": func(termsList ...[]string) string {
				var b strings.Builder
				for _, terms := range termsList {
					for _, term := range terms {
						if b.Len() > 0 {
							b.WriteString(" ")
						}
						hasSpace := false
						for _, char := range term {
							if unicode.IsSpace(char) {
								hasSpace = true
								break
							}
						}
						if hasSpace {
							b.WriteString(`"` + term + `"`)
						} else {
							b.WriteString(term)
						}
					}
				}
				return b.String()
			},
		}
		tmpl, err := template.New("search.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/search.html")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.ExecuteTemplate(w, r, tmpl, &response)
	}

	request := Request{
		Parent:         r.Form.Get("parent"),
		MustInclude:    r.Form.Get("mustInclude"),
		MayInclude:     r.Form.Get("mayInclude"),
		Exclude:        r.Form.Get("exclude"),
		MandatoryTerms: r.Form["mandatoryTerm"],
		OptionalTerms:  r.Form["optionalTerm"],
		ExcludeTerms:   r.Form["excludeTerm"],
		FileTypes:      r.Form["fileType"],
	}

	var response Response
	response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
	response.CDNDomain = nbrew.CDNDomain
	response.IsDatabaseFS = true
	response.SitePrefix = sitePrefix
	response.UserID = user.UserID
	response.Username = user.Username
	response.DisableReason = user.DisableReason
	response.Parent = path.Clean(strings.Trim(request.Parent, "/"))
	// Mandatory terms.
	for _, mandatoryTerm := range request.MandatoryTerms {
		response.MandatoryTerms = append(response.MandatoryTerms, quoteReplacer.Replace(mandatoryTerm))
	}
	for _, mandatoryTerm := range splitTerms(request.MustInclude) {
		response.MandatoryTerms = append(response.MandatoryTerms, quoteReplacer.Replace(mandatoryTerm))
	}
	// Optional terms.
	for _, optionalTerm := range request.OptionalTerms {
		response.OptionalTerms = append(response.OptionalTerms, quoteReplacer.Replace(optionalTerm))
	}
	for _, optionalTerm := range splitTerms(request.MayInclude) {
		response.OptionalTerms = append(response.OptionalTerms, quoteReplacer.Replace(optionalTerm))
	}
	// Exclude terms.
	for _, exludeTerm := range request.ExcludeTerms {
		response.ExcludeTerms = append(response.ExcludeTerms, quoteReplacer.Replace(exludeTerm))
	}
	for _, exludeTerm := range splitTerms(request.Exclude) {
		response.ExcludeTerms = append(response.ExcludeTerms, quoteReplacer.Replace(exludeTerm))
	}
	// Allowed file types.
	response.AvailableFileTypes = make([]string, 0, len(editableExts)+len(imgExts)+2)
	availableFileTypes := make(map[string]struct{})
	for _, ext := range editableExts {
		response.AvailableFileTypes = append(response.AvailableFileTypes, ext)
		availableFileTypes[ext] = struct{}{}
	}
	for _, ext := range imgExts {
		response.AvailableFileTypes = append(response.AvailableFileTypes, ext)
		availableFileTypes[ext] = struct{}{}
	}
	fmt.Printf("videoExts: %#v\n", videoExts)
	for _, ext := range videoExts {
		response.AvailableFileTypes = append(response.AvailableFileTypes, ext)
		availableFileTypes[ext] = struct{}{}
	}
	response.AvailableFileTypes = append(response.AvailableFileTypes, ".json", "folder")
	availableFileTypes[".json"] = struct{}{}
	availableFileTypes["folder"] = struct{}{}
	// File types.
	if len(request.FileTypes) > 0 {
		for _, value := range request.FileTypes {
			_, ok := availableFileTypes[value]
			if ok {
				response.FileTypes = append(response.FileTypes, value)
			}
		}
		slices.Sort(response.FileTypes)
		response.FileTypes = slices.Compact(response.FileTypes)
	}
	if !fs.ValidPath(response.Parent) || strings.Contains(response.Parent, "\\") {
		response.Parent = "."
	} else {
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
			if err != nil || !fileInfo.IsDir() {
				response.Parent = "."
			}
		}
	}
	if len(response.MandatoryTerms) == 0 && len(response.OptionalTerms) == 0 {
		writeResponse(w, r, response)
		return
	}
	var err error
	var parentFilter sq.Expression
	parent := path.Join(sitePrefix, response.Parent)
	if parent == "." {
		parentFilter = sq.Expr("(" +
			"files.file_path LIKE 'notes/%' ESCAPE '\\'" +
			" OR files.file_path LIKE 'pages/%' ESCAPE '\\'" +
			" OR files.file_path LIKE 'posts/%' ESCAPE '\\'" +
			" OR files.file_path LIKE 'output/%' ESCAPE '\\'" +
			")")
	} else {
		parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(parent)+"/%")
	}
	fileTypeFilter := sq.Expr("1 = 1")
	if len(response.FileTypes) > 0 {
		var folderSelected bool
		exts := make([]string, 0, len(response.FileTypes))
		for _, value := range response.FileTypes {
			if value == "folder" {
				folderSelected = true
			} else {
				exts = append(exts, value)
			}
		}
		var b strings.Builder
		var args []any
		if len(exts) == 0 && folderSelected {
			b.WriteString("files.is_dir")
		} else if len(exts) > 0 && !folderSelected {
			b.WriteString("NOT files.is_dir AND (")
			for i, ext := range exts {
				if i > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString("files.file_path LIKE {} ESCAPE '\\'")
				args = append(args, "%"+wildcardReplacer.Replace(ext))
			}
			b.WriteString(")")
		} else {
			b.WriteString("(files.is_dir")
			for _, ext := range exts {
				b.WriteString(" OR files.file_path LIKE {} ESCAPE '\\'")
				args = append(args, "%"+wildcardReplacer.Replace(ext))
			}
			b.WriteString(")")
		}
		fileTypeFilter = sq.Expr(b.String(), args...)
	}
	switch databaseFS.Dialect {
	case "sqlite":
		var b strings.Builder
		for _, mandatoryTerm := range response.MandatoryTerms {
			if b.Len() > 0 {
				b.WriteString(" AND ")
			}
			b.WriteString(`"` + mandatoryTerm + `"`)
		}
		if len(response.OptionalTerms) > 0 {
			if len(response.MandatoryTerms) > 0 {
				b.WriteString(` AND ("` + response.MandatoryTerms[len(response.MandatoryTerms)-1] + `"`)
			}
			for _, optionalTerm := range response.OptionalTerms {
				if b.Len() > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString(`"` + optionalTerm + `"`)
			}
			if len(response.MandatoryTerms) > 0 {
				b.WriteString(")")
			}
		}
		for _, excludeTerm := range response.ExcludeTerms {
			if b.Len() > 0 {
				b.WriteString(" NOT ")
			}
			b.WriteString(`"` + excludeTerm + `"`)
		}
		ftsQuery := b.String()
		response.Matches, err = sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" JOIN files_fts5 ON files_fts5.rowid = files.rowid" +
				" WHERE {parentFilter}" +
				" AND files_fts5 MATCH {ftsQuery}" +
				" AND {fileTypeFilter}" +
				" ORDER BY files_fts5.rank, files.creation_time DESC",
			Values: []any{
				sq.Param("parentFilter", parentFilter),
				sq.StringParam("ftsQuery", ftsQuery),
				sq.Param("fileTypeFilter", fileTypeFilter),
			},
		}, func(row *sq.Row) Match {
			match := Match{
				FileID:       row.UUID("files.file_id"),
				FilePath:     row.String("files.file_path"),
				IsDir:        row.Bool("files.is_dir"),
				Preview:      row.String("CASE WHEN files.file_path LIKE '%.json' ESCAPE '\\' THEN '' ELSE substr(files.text, 1, 500) END"),
				ModTime:      row.Time("files.mod_time"),
				CreationTime: row.Time("files.creation_time"),
			}
			if sitePrefix != "" {
				_, match.FilePath, _ = strings.Cut(match.FilePath, "/")
			}
			return match
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
	case "postgres":
		// TODO: SELECT * FROM files WHERE files.fts @@ ((to_tsquery('english', 'apple') || phraseto_tsquery('english', 'steve jobs')) && !!to_tsquery('english', 'iphone'))
	case "mysql":
		// TODO: SELECT * FROM files WHERE MATCH (file_name, text) AGAINST ('("apple" "steve jobs") -"iphone"' IN BOOLEAN MODE)
	}
	writeResponse(w, r, response)
}

func splitTerms(s string) []string {
	var terms []string
	var b strings.Builder
	inString := false
	for _, char := range s {
		if char == '"' || char == '“' || char == '”' || char == '„' || char == '‟' {
			inString = !inString
			if b.Len() > 0 {
				terms = append(terms, b.String())
				b.Reset()
			}
			continue
		}
		if inString {
			b.WriteRune(char)
			continue
		}
		if unicode.IsSpace(char) {
			if b.Len() > 0 {
				terms = append(terms, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteRune(char)
	}
	if b.Len() > 0 {
		terms = append(terms, b.String())
	}
	return terms
}
