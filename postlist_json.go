package notebrew

import (
	"bytes"
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
	"time"
)

func (nbrew *Notebrew) postlistJSON(w http.ResponseWriter, r *http.Request, user User, sitePrefix, category string) {
	type Request struct {
		PostsPerPage int `json:"postsPerPage"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		Category          string            `json:"category"`
		PostsPerPage      int               `json:"postsPerPage"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}
	normalizeRequest := func(request Request) Request {
		if request.PostsPerPage <= 0 {
			request.PostsPerPage = 100
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
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("postlist_json.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/postlist_json.html")
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
		response.Category = category
		b, err := fs.ReadFile(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "posts", category, "postlist.json"))
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
		response.PostsPerPage = request.PostsPerPage
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
					"from": "postlist.json",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "posts", category, "postlist.json"), http.StatusFound)
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
			request.PostsPerPage, _ = strconv.Atoi(r.Form.Get("postsPerPage"))
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
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "posts", category, "postlist.json"), 0644)
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
		response := Response{
			ContentBaseURL: nbrew.ContentBaseURL(sitePrefix),
			SitePrefix:     sitePrefix,
			PostsPerPage:   request.PostsPerPage,
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
		postListTemplate, err := siteGen.PostListTemplate(r.Context(), category)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		count, err := siteGen.GeneratePostList(r.Context(), category, postListTemplate)
		if err != nil {
			if !errors.As(err, &response.RegenerationStats.TemplateError) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		response.RegenerationStats.Count = count
		response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
