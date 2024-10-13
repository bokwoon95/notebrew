package notebrew

import (
	"encoding/json"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/bokwoon95/notebrew/sq"
)

func (nbrew *Notebrew) updateprofile(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Username              string `json:"username"`
		TimezoneOffsetSeconds int    `json:"timezoneOffsetSeconds"`
	}
	type Response struct {
		UserID                ID         `json:"userID"`
		Username              string     `json:"username"`
		DisableReason         string     `json:"disableReason"`
		TimezoneOffsetSeconds int        `json:"timezoneOffsetSeconds"`
		Error                 string     `json:"error"`
		FormErrors            url.Values `json:"formErrors"`
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
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("updateprofile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/updateprofile.html")
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
		response.TimezoneOffsetSeconds = user.TimezoneOffsetSeconds
		if response.Error != "" {
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
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/users/updateprofile/", http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "updateprofile",
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/users/profile/", http.StatusFound)
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
			request.Username = r.Form.Get("username")
			if s := r.Form.Get("timezoneOffsetSeconds"); s != "" {
				timezoneOffsetSeconds, err := strconv.Atoi(s)
				if err != nil {
					nbrew.BadRequest(w, r, fmt.Errorf("timezoneOffsetSeconds: %s is not an integer", s))
					return
				}
				request.TimezoneOffsetSeconds = timezoneOffsetSeconds
			}
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			UserID:                user.UserID,
			Username:              strings.TrimSpace(request.Username),
			TimezoneOffsetSeconds: request.TimezoneOffsetSeconds,
			FormErrors:            url.Values{},
		}
		// username
		if user.Username == "" {
			if response.Username != "" {
				response.FormErrors.Add("username", "cannot change default user's username")
			}
		} else {
			if response.Username == "" {
				response.FormErrors.Add("username", "required")
			} else {
				for _, char := range response.Username {
					if char == ' ' {
						response.FormErrors.Add("username", "cannot include space")
						break
					}
					if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
						response.FormErrors.Add("username", fmt.Sprintf("cannot include character %q", string(char)))
						break
					}
				}
				if len(response.Username) > 30 {
					response.FormErrors.Add("username", "cannot exceed 30 characters")
				}
			}
		}
		if !response.FormErrors.Has("username") && user.Username != response.Username {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE username = {username}",
				Values: []any{
					sq.StringParam("username", response.Username),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if exists {
				response.FormErrors.Add("username", "username already used by an existing user account")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		var assignments []sq.Expression
		if response.Username != user.Username {
			assignments = append(assignments, sq.Expr("username = {}", response.Username))
		}
		if response.TimezoneOffsetSeconds != user.TimezoneOffsetSeconds {
			assignments = append(assignments, sq.Expr("timezone_offset_seconds = {}", response.TimezoneOffsetSeconds))
		}
		if len(assignments) == 0 {
			writeResponse(w, r, response)
			return
		}
		_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE users SET {assignments} WHERE user_id = {userID}",
			Values: []any{
				sq.Param("assignments", assignments),
				sq.UUIDParam("userID", user.UserID),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
