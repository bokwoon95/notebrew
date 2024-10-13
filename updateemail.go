package notebrew

import (
	"encoding/json"
	"html/template"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strings"

	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/crypto/bcrypt"
)

func (nbrew *Notebrew) updateemail(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type Response struct {
		UserID        ID         `json:"userID"`
		Username      string     `json:"username"`
		DisableReason string     `json:"disableReason"`
		Email         string     `json:"email"`
		Error         string     `json:"error"`
		FormErrors    url.Values `json:"formErrors"`
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
			tmpl, err := template.New("updateemail.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/updateemail.html")
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
		response.Email = user.Email
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
				http.Redirect(w, r, "/users/updateemail/", http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "updateemail",
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
			request.Password = r.Form.Get("password")
			request.Email = r.Form.Get("email")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Email:      request.Email,
			FormErrors: url.Values{},
		}
		// password
		if request.Password == "" {
			response.FormErrors.Add("password", "required")
		} else {
			passwordHash, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM users WHERE user_id = {userID}",
				Values: []any{
					sq.UUIDParam("userID", user.UserID),
				},
			}, func(row *sq.Row) []byte {
				return row.Bytes(nil, "password_hash")
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			err = bcrypt.CompareHashAndPassword(passwordHash, []byte(request.Password))
			if err != nil {
				response.FormErrors.Add("password", "password is incorrect")
			}
		}
		// email
		if response.Email == "" {
			response.FormErrors.Add("email", "required")
		} else if response.Email == user.Email {
			response.FormErrors.Add("email", "email is the same")
		} else {
			_, err := mail.ParseAddress(response.Email)
			if err != nil {
				response.FormErrors.Add("email", "invalid email address")
			} else {
				exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT 1 FROM users WHERE email = {email}",
					Values: []any{
						sq.StringParam("email", response.Email),
					},
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if exists {
					response.FormErrors.Add("email", "email already used by an existing user account")
				}
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE users SET email = {email} WHERE user_id = {userID}",
			Values: []any{
				sq.Param("email", response.Email),
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
