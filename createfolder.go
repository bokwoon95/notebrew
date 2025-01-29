package notebrew

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) createfolder(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		FileID ID     `json:"fileID"`
		Parent string `json:"parent"`
		Name   string `json:"name"`
	}
	type Response struct {
		ContentBaseURL string     `json:"contentBaseURL"`
		SitePrefix     string     `json:"sitePrefix"`
		UserID         ID         `json:"userID"`
		Username       string     `json:"username"`
		DisableReason  string     `json:"disableReason"`
		Parent         string     `json:"parent"`
		Name           string     `json:"name"`
		Error          string     `json:"error"`
		FormErrors     url.Values `json:"formErrors"`
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
			tmpl, err := template.New("createfolder.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createfolder.html")
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
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages":
			break
		case "posts":
			if tail != "" {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next != "themes" {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
		if err != nil || !fileInfo.IsDir() {
			response.Error = "InvalidParent"
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
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "createfolder")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":   "createfolder",
					"parent": response.Parent,
					"name":   response.Name,
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
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
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			FormErrors: make(url.Values),
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages":
			break
		case "posts":
			if tail != "" {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next != "themes" {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
		if err != nil || !fileInfo.IsDir() {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		if head == "notes" {
			response.Name = filenameSafe(request.Name)
		} else {
			response.Name = urlSafe(request.Name)
		}
		if response.Name == "" {
			response.FormErrors.Add("name", "required")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		_, ok := AllowedFileTypes[strings.ToLower(path.Ext(response.Name))]
		if ok {
			response.FormErrors.Add("name", "cannot end in a file extension")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		switch head {
		case "pages":
			if (tail == "" && response.Name == "posts") ||
				(tail == "" && response.Name == "themes") ||
				(tail != "" && response.Name == "index") {
				response.FormErrors.Add("name", "this name is not allowed")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			err := nbrew.FS.MkdirAll(path.Join(sitePrefix, "output", tail, response.Name), 0755)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		case "posts":
			err := nbrew.FS.MkdirAll(path.Join(sitePrefix, "output", response.Parent, response.Name), 0755)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		err = nbrew.FS.Mkdir(path.Join(sitePrefix, response.Parent, response.Name), 0755)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				if head == "posts" {
					response.FormErrors.Add("name", "category already exists")
				} else {
					response.FormErrors.Add("name", "folder already exists")
				}
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if response.Parent == "posts" {
			category := response.Name
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
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				b, err := fs.ReadFile(RuntimeFS, "embed/post.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, response.Parent, category, "post.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, response.Parent, category, "postlist.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				tmpl, err := siteGen.ParseTemplate(groupctx, path.Join("posts", category, "postlist.html"), string(b))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePostListPage(groupctx, category, tmpl, 1, 1, nil)
				if err != nil {
					return err
				}
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.json")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, response.Parent, category, "postlist.json"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
			err = group.Wait()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
