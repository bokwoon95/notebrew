package notebrew

import (
	"encoding/json"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/crypto/bcrypt"
)

func (nbrew *Notebrew) changepassword(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		OldPassword     string `json:"oldPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	type Response struct {
		UserID        ID         `json:"userID"`
		Username      string     `json:"username"`
		DisableReason string     `json:"disableReason"`
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
			tmpl, err := template.New("changepassword.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/changepassword.html")
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
				http.Redirect(w, r, "/users/changepassword/", http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "changepassword",
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/users/login/", http.StatusFound)
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
			request.OldPassword = r.Form.Get("oldPassword")
			request.NewPassword = r.Form.Get("newPassword")
			request.ConfirmPassword = r.Form.Get("confirmPassword")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: url.Values{},
		}
		// oldPassword
		if request.OldPassword == "" {
			response.FormErrors.Add("oldPassword", "required")
		} else {
			oldPasswordHash, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
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
			err = bcrypt.CompareHashAndPassword(oldPasswordHash, []byte(request.OldPassword))
			if err != nil {
				response.FormErrors.Add("oldPassword", "password is incorrect")
			}
		}
		// newPassword
		if request.NewPassword == "" {
			response.FormErrors.Add("newPassword", "required")
		} else {
			if utf8.RuneCountInString(request.NewPassword) < 8 {
				response.FormErrors.Add("newPassword", "password must be at least 8 characters")
			}
			if _, ok := commonPasswords[request.NewPassword]; ok {
				response.FormErrors.Add("newPassword", "password is too common")
			}
		}
		// confirmPassword
		if !response.FormErrors.Has("newPassword") {
			if request.ConfirmPassword == "" {
				response.FormErrors.Add("confirmPassword", "required")
			} else {
				if request.NewPassword != request.ConfirmPassword {
					response.FormErrors.Add("confirmPassword", "password does not match")
				}
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		tx, err := nbrew.DB.Begin()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer tx.Rollback()
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM session WHERE user_id = {userID}",
			Values: []any{
				sq.UUIDParam("userID", user.UserID),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE users SET password_hash = {newPasswordHash}, reset_token_hash = NULL WHERE user_id = {userID}",
			Values: []any{
				sq.StringParam("newPasswordHash", string(newPasswordHash)),
				sq.UUIDParam("userID", user.UserID),
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
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
