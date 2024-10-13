package notebrew

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) rename(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent string `json:"parent"`
		Name   string `json:"name"`
		To     string `json:"to"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		Parent            string            `json:"parent"`
		Name              string            `json:"name"`
		From              string            `json:"from"`
		To                string            `json:"to"`
		Prefix            string            `json:"prefix"`
		Ext               string            `json:"ext"`
		IsDir             bool              `json:"isDir"`
		Error             string            `json:"status"`
		FormErrors        url.Values        `json:"formErrors"`
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
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
			}
			tmpl, err := template.New("rename.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/rename.html")
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
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		response.Name = r.Form.Get("name")
		if response.Name == "" || strings.Contains(response.Name, "/") {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, response.Name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.IsDir = fileInfo.IsDir()
		if response.IsDir {
			response.From = response.Name
		} else {
			remainder := response.Name
			if head == "posts" {
				i := strings.Index(remainder, "-")
				if i >= 0 {
					prefix, suffix := remainder[:i], remainder[i+1:]
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = suffix
						}
					}
				} else {
					prefix := strings.TrimSuffix(remainder, path.Ext(remainder))
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = path.Ext(remainder)
						}
					}
				}
			}
			ext := path.Ext(remainder)
			response.From = strings.TrimSuffix(remainder, ext)
			response.Ext = ext
		}
		switch head {
		case "notes", "pages", "posts", "output", "imports", "exports":
			if response.Parent == "pages" && (response.Name == "index.html" || response.Name == "404.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			if head == "posts" && (response.Name == "post.html" || response.Name == "postlist.html" || response.Name == "postlist.json") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
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
				redirectURL := "/" + path.Join("files", sitePrefix, "rename") + "/" +
					"?parent=" + url.QueryEscape(response.Parent) +
					"&name=" + url.QueryEscape(response.Name)
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":    "rename",
					"parent":  response.Parent,
					"oldName": response.Name,
					"newName": response.Prefix + response.To + response.Ext,
					"isDir":   response.IsDir,
				},
				"regenerationStats": response.RegenerationStats,
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
			request.Parent = r.Form.Get("parent")
			request.Name = r.Form.Get("name")
			request.To = r.Form.Get("to")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Name:       request.Name,
			To:         request.To,
			FormErrors: make(url.Values),
		}
		if response.Name == "" || strings.Contains(response.Name, "/") {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, response.Name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.IsDir = fileInfo.IsDir()
		if response.IsDir {
			response.From = response.Name
		} else {
			remainder := response.Name
			ext := path.Ext(remainder)
			if head == "posts" && ext == ".md" {
				prefix, suffix, ok := strings.Cut(remainder, "-")
				if ok {
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = suffix
						}
					}
				} else {
					prefix := strings.TrimSuffix(remainder, ext)
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = ext
						}
					}
				}
			}
			response.From = strings.TrimSuffix(remainder, ext)
			response.Ext = ext
		}
		if response.To == "" {
			response.FormErrors.Add("to", fmt.Sprintf("cannot be empty"))
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		switch head {
		case "notes":
			var b strings.Builder
			b.Grow(len(response.To))
			for _, char := range response.To {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(filenameReplacementChars) {
					b.WriteRune(char)
					continue
				}
				replacementChar := filenameReplacementChars[n]
				if replacementChar == 0 {
					b.WriteRune(char)
					continue
				}
				b.WriteRune(replacementChar)
			}
			response.To = b.String()
		case "pages", "posts", "output", "imports", "exports":
			if response.Parent == "pages" && (response.Name == "index.html" || response.Name == "404.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			if head == "posts" && (response.Name == "post.html" || response.Name == "postlist.html" || response.Name == "postlist.json") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			for _, char := range response.To {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isURLUnsafe) || !isURLUnsafe[n] {
					continue
				}
				if char == ' ' {
					response.FormErrors.Add("to", fmt.Sprintf("cannot include space"))
				} else {
					response.FormErrors.Add("to", fmt.Sprintf("cannot include character %q", string(char)))
				}
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		oldName := path.Join(sitePrefix, response.Parent, response.Name)
		newName := path.Join(sitePrefix, response.Parent, response.Prefix+response.To+response.Ext)
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), newName)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			response.FormErrors.Add("to", "a file with this name already exists")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		err = nbrew.FS.WithContext(r.Context()).Rename(oldName, newName)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		switch head {
		case "pages":
			// example: pages/foobar.html (must be a file) and pages/foobar
			// (must be a dir) are counterparts that share the same output
			// directory (output/foobar).
			var counterpart string
			if !response.IsDir {
				counterpart = strings.TrimPrefix(oldName, ".html")
			} else {
				counterpart = oldName + ".html"
			}
			var counterpartExists bool
			counterpartFileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				counterpartExists = counterpartFileInfo.IsDir() != response.IsDir
			}
			oldOutputDir := path.Join(sitePrefix, "output", tail, strings.TrimSuffix(response.Name, path.Ext(response.Name)))
			newOutputDir := path.Join(sitePrefix, "output", tail, response.To)
			if !counterpartExists {
				// Fast path: if the counterpart doesn't exist, we can just
				// rename the entire output directory.
				err := nbrew.FS.WithContext(r.Context()).Rename(oldOutputDir, newOutputDir)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				// Otherwise, we have to loop over each corresponding item in
				// the output directory one by one to rename it.
				err = nbrew.FS.WithContext(r.Context()).MkdirAll(newOutputDir, 0755)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(oldOutputDir)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				group, groupctx := errgroup.WithContext(r.Context())
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() == response.IsDir {
						name := dirEntry.Name()
						group.Go(func() (err error) {
							defer stacktrace.RecoverPanic(&err)
							return nbrew.FS.WithContext(groupctx).Rename(path.Join(oldOutputDir, name), path.Join(newOutputDir, name))
						})
					}
				}
				err = group.Wait()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			}
			var parentPage string
			if response.Parent == "pages" {
				parentPage = "pages/index.html"
			} else {
				parentPage = response.Parent + ".html"
			}
			file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, parentPage))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					writeResponse(w, r, response)
					return
				}
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
		case "posts":
			// example: posts/foobar.md (must be a file) and posts/foobar (must
			// be a dir) are counterparts that share the same output directory
			// (output/posts/foobar).
			var counterpart string
			if !response.IsDir {
				counterpart = strings.TrimPrefix(oldName, ".md")
			} else {
				counterpart = oldName + ".md"
			}
			var counterpartExists bool
			counterpartFileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				counterpartExists = counterpartFileInfo.IsDir() != response.IsDir
			}
			oldOutputDir := path.Join(sitePrefix, "output/posts", tail, strings.TrimSuffix(response.Name, path.Ext(response.Name)))
			newOutputDir := path.Join(sitePrefix, "output/posts", tail, response.Prefix+response.To)
			// Fast path: if the counterpart doesn't exist, we can just rename
			// the entire output directory.
			if !counterpartExists {
				err := nbrew.FS.WithContext(r.Context()).Rename(oldOutputDir, newOutputDir)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else {
				// Otherwise, we have to loop over each corresponding item in
				// the output directory one by one to rename it.
				err := nbrew.FS.WithContext(r.Context()).MkdirAll(newOutputDir, 0755)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(oldOutputDir)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				group, groupctx := errgroup.WithContext(r.Context())
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() == response.IsDir {
						name := dirEntry.Name()
						group.Go(func() (err error) {
							defer stacktrace.RecoverPanic(&err)
							return nbrew.FS.WithContext(groupctx).Rename(path.Join(oldOutputDir, name), path.Join(newOutputDir, name))
						})
					}
				}
				err = group.Wait()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
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
			category := tail
			tmpl, err := siteGen.PostListTemplate(r.Context(), category)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			startedAt := time.Now()
			count, err := siteGen.GeneratePostList(r.Context(), category, tmpl)
			if err != nil {
				if errors.As(err, &response.RegenerationStats.TemplateError) {
					writeResponse(w, r, response)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = count
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
		case "output":
			if fileInfo.IsDir() {
				writeResponse(w, r, response)
				return
			}
			fileType := AllowedFileTypes[response.Ext]
			next, _, _ := strings.Cut(tail, "/")
			if next == "posts" {
				if fileType.Has(AttributeImg) {
					parentPost := tail + ".md"
					file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, parentPost))
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
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
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
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, parentPost)
							}
						}
						creationTime = CreationTime(absolutePath, fileInfo)
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
					category := path.Dir(strings.TrimPrefix(parentPost, "posts/"))
					if category == "." {
						category = ""
					}
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
					err = siteGen.GeneratePost(r.Context(), parentPost, b.String(), startedAt, creationTime, tmpl)
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
			} else if next != "themes" {
				if fileType.Has(AttributeImg) || fileType.Ext == ".md" {
					var parentPage string
					if tail == "" {
						parentPage = "pages/index.html"
					} else {
						parentPage = path.Join("pages", tail+".html")
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
