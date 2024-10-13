package notebrew

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/bokwoon95/notebrew/sq"
)

func (nbrew *Notebrew) deletesite(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		SiteName        string `json:"siteName"`
		ConfirmSiteName string `json:"confirmSiteName"`
	}
	type Response struct {
		UserID          ID         `json:"userID"`
		Username        string     `json:"username"`
		DisableReason   string     `json:"disableReason"`
		SiteName        string     `json:"siteName"`
		ConfirmSiteName string     `json:"confirmSiteName"`
		Error           string     `json:"error"`
		FormErrors      url.Values `json:"formErrors"`
	}

	validateSiteName := func(siteName string) bool {
		if len(siteName) > 30 {
			return false
		}
		for _, char := range siteName {
			if (char < 'a' && char > 'z') && (char < '0' && char > '9') && char != '-' && char != '.' {
				return false
			}
		}
		return true
	}

	getSitePermissions := func(siteName, username string) (siteNotFound, userIsAuthorized bool, err error) {
		if nbrew.DB == nil {
			return false, true, nil
		}
		userIsAuthorized, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "SELECT {*}" +
				" FROM site" +
				" LEFT JOIN site_owner ON site_owner.site_id = site.site_id" +
				" LEFT JOIN users ON users.user_id = site_owner.user_id" +
				" WHERE site.site_name = {siteName}" +
				" AND users.username = {username}",
			Values: []any{
				sq.StringParam("siteName", siteName),
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("users.user_id IS NOT NULL")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return true, false, nil
			}
			return false, false, err
		}
		return siteNotFound, userIsAuthorized, nil
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
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
				"username":   func() string { return user.Username },
			}
			tmpl, err := template.New("deletesite.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/deletesite.html")
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
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}

		response.SiteName = r.Form.Get("name")
		if response.SiteName == "" {
			response.Error = "SiteNameNotProvided"
			writeResponse(w, r, response)
			return
		}
		valid := validateSiteName(response.SiteName)
		if !valid {
			response.Error = "InvalidSiteName"
			writeResponse(w, r, response)
			return
		}
		siteNotFound, userIsAuthorized, err := getSitePermissions(response.SiteName, user.Username)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if siteNotFound {
			response.Error = "SiteNotFound"
			writeResponse(w, r, response)
			return
		}
		if !userIsAuthorized {
			response.Error = "NotAuthorized"
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
				b, err := json.Marshal(&response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				w.Write(b)
				return
			}
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/files/deletesite/?name="+url.QueryEscape(response.SiteName), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":     "deletesite",
					"siteName": response.SiteName,
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/files/", http.StatusFound)
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
			request.SiteName = r.Form.Get("siteName")
			request.ConfirmSiteName = r.Form.Get("confirmSiteName")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors:      make(url.Values),
			SiteName:        request.SiteName,
			ConfirmSiteName: request.ConfirmSiteName,
		}
		if response.SiteName == "" {
			response.Error = "SiteNameNotProvided"
			writeResponse(w, r, response)
			return
		}
		ok := validateSiteName(response.SiteName)
		if !ok {
			response.Error = "InvalidSiteName"
			writeResponse(w, r, response)
			return
		}
		siteNotFound, userIsAuthorized, err := getSitePermissions(response.SiteName, user.Username)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if siteNotFound {
			response.Error = "SiteNotFound"
			writeResponse(w, r, response)
			return
		}
		if !userIsAuthorized {
			response.Error = "NotAuthorized"
			writeResponse(w, r, response)
			return
		}
		if response.ConfirmSiteName != response.SiteName {
			response.FormErrors.Add("confirmSiteName", "site name does not match")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}

		var sitePrefix string
		if strings.Contains(response.SiteName, ".") {
			sitePrefix = response.SiteName
		} else {
			sitePrefix = "@" + response.SiteName
		}
		err = nbrew.FS.RemoveAll(sitePrefix)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if nbrew.DB != nil {
			tx, err := nbrew.DB.Begin()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer tx.Rollback()
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "DELETE FROM site_owner WHERE EXISTS (" +
					"SELECT 1 FROM site WHERE site.site_id = site_owner.site_id AND site.site_name = {siteName}" +
					")",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "DELETE FROM site_user WHERE EXISTS (" +
					"SELECT 1 FROM site WHERE site.site_id = site_user.site_id AND site.site_name = {siteName}" +
					")",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM site WHERE site_name = {siteName}",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			err = tx.Commit()
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
