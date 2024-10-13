package notebrew

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/mileusna/useragent"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) login(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		HasMailer              bool           `json:"hasMailer"`
		Username               string         `json:"username"`
		RequireCaptcha         bool           `json:"requireCaptcha"`
		CaptchaWidgetScriptSrc template.URL   `json:"captchaWidgetScriptSrc"`
		CaptchaWidgetClass     string         `json:"captchaWidgetClass"`
		CaptchaSiteKey         string         `json:"captchaSiteKey"`
		CaptchaResponseName    string         `json:"captchaResponseName"`
		Error                  string         `json:"error"`
		FormErrors             url.Values     `json:"formErrors"`
		SessionToken           string         `json:"sessionToken"`
		Redirect               string         `json:"redirect"`
		PostRedirectGet        map[string]any `json:"postRedirectGet"`
	}

	sanitizeRedirect := func(redirect string) string {
		if r.Host != nbrew.CMSDomain {
			return ""
		}
		uri, err := url.Parse(path.Clean(redirect))
		if err != nil {
			return ""
		}
		head, tail, _ := strings.Cut(strings.Trim(uri.Path, "/"), "/")
		if head != "files" && head != "users" {
			return ""
		}
		if tail == "" {
			return ""
		}
		uri = &url.URL{
			Path:     strings.Trim(uri.Path, "/"),
			RawQuery: uri.RawQuery,
		}
		if path.Ext(uri.Path) == "" {
			uri.Path = "/" + uri.Path + "/"
		} else {
			uri.Path = "/" + uri.Path
		}
		return uri.String()
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			response.CaptchaSiteKey = nbrew.CaptchaConfig.SiteKey
			if nbrew.CaptchaConfig.VerificationURL != "" {
				ip := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs).As16()
				failedLoginAttempts, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT {*} FROM ip_login WHERE ip = {ip}",
					Values: []any{
						sq.BytesParam("ip", ip[:]),
					},
				}, func(row *sq.Row) int {
					return row.Int("failed_login_attempts")
				})
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if failedLoginAttempts >= 3 {
					response.RequireCaptcha = true
				}
			}
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
			funcMap := map[string]any{
				"join":       path.Join,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
			}
			tmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/login.html")
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}

		err := r.ParseForm()
		if err != nil {
			nbrew.BadRequest(w, r, err)
			return
		}
		var response Response
		_, err = nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.HasMailer = nbrew.Mailer != nil
		response.CaptchaWidgetScriptSrc = nbrew.CaptchaConfig.WidgetScriptSrc
		response.CaptchaWidgetClass = nbrew.CaptchaConfig.WidgetClass
		response.CaptchaSiteKey = nbrew.CaptchaConfig.SiteKey
		response.CaptchaResponseName = nbrew.CaptchaConfig.ResponseTokenName
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		if r.Form.Has("401") {
			response.Error = "NotAuthenticated"
			writeResponse(w, r, response)
			return
		}
		response.Redirect = sanitizeRedirect(r.Form.Get("redirect"))
		if !user.UserID.IsZero() {
			response.Error = "AlreadyAuthenticated"
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
		if !user.UserID.IsZero() {
			http.Redirect(w, r, "/"+path.Join("files")+"/", http.StatusFound)
			return
		}
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if response.Error == "IncorrectLoginCredentials" || response.Error == "ErrUserNotFound" {
				ip := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs).As16()
				if nbrew.Dialect == sq.DialectMySQL {
					_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
						Dialect: nbrew.Dialect,
						Format: "INSERT INTO ip_login (ip, failed_login_attempts) VALUES ({ip}, 1)" +
							" ON DUPLICATE KEY UPDATE failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1",
						Values: []any{
							sq.BytesParam("ip", ip[:]),
						},
					})
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
				} else {
					_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
						Dialect: nbrew.Dialect,
						Format: "INSERT INTO ip_login (ip, failed_login_attempts) VALUES ({ip}, 1)" +
							" ON CONFLICT (ip) DO UPDATE SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1",
						Values: []any{
							sq.BytesParam("ip", ip[:]),
						},
					})
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
				}
				_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "UPDATE users SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1 WHERE username = {username}",
					Values: []any{
						sq.StringParam("username", response.Username),
					},
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			} else if response.Error == "" {
				ip := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs).As16()
				_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "DELETE FROM ip_login WHERE ip = {ip}",
					Values: []any{
						sq.BytesParam("ip", ip[:]),
					},
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "UPDATE users SET failed_login_attempts = NULL WHERE username = {username}",
					Values: []any{
						sq.StringParam("username", response.Username),
					},
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
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
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				var query string
				if response.Redirect != "" {
					query = "?redirect=" + url.QueryEscape(response.Redirect)
				}
				http.Redirect(w, r, "/users/login/"+query, http.StatusFound)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Path:     "/",
				Name:     "session",
				Value:    response.SessionToken,
				Secure:   r.TLS != nil,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int((time.Hour * 24 * 365).Seconds()),
			})
			if response.Redirect != "" {
				http.Redirect(w, r, response.Redirect, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files")+"/", http.StatusFound)
		}

		var request Request
		var redirect string
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
				err := r.ParseMultipartForm(2 << 20 /* 2MB */)
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
			request.Password = r.Form.Get("password")
			request.CaptchaResponse = r.Form.Get(nbrew.CaptchaConfig.ResponseTokenName)
			redirect = r.Form.Get("redirect")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Username:   strings.TrimPrefix(request.Username, "@"),
			FormErrors: make(url.Values),
			Redirect:   sanitizeRedirect(redirect),
		}

		if response.Username == "" {
			response.FormErrors.Add("username", "required")
		}
		if request.Password == "" {
			response.FormErrors.Add("password", "required")
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}

		var err error
		var email string
		var passwordHash []byte
		var failedLoginAttempts int
		var userNotFound bool
		if strings.Contains(response.Username, "@") {
			email = response.Username
		}
		if email != "" {
			result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", email),
				},
			}, func(row *sq.Row) (result struct {
				Username            string
				PasswordHash        []byte
				FailedLoginAttempts int
			}) {
				result.Username = row.String("username")
				result.PasswordHash = row.Bytes(nil, "password_hash")
				result.FailedLoginAttempts = row.Int("failed_login_attempts")
				return result
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				userNotFound = true
			}
			passwordHash = result.PasswordHash
			failedLoginAttempts = result.FailedLoginAttempts
		} else {
			result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM users WHERE username = {username}",
				Values: []any{
					sq.StringParam("username", response.Username),
				},
			}, func(row *sq.Row) (result struct {
				PasswordHash        []byte
				FailedLoginAttempts int
			}) {
				result.PasswordHash = row.Bytes(nil, "password_hash")
				result.FailedLoginAttempts = row.Int("failed_login_attempts")
				return result
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				userNotFound = true
			}
			passwordHash = result.PasswordHash
			failedLoginAttempts = result.FailedLoginAttempts
		}

		if nbrew.CaptchaConfig.VerificationURL != "" {
			if failedLoginAttempts >= 3 {
				response.RequireCaptcha = true
			} else {
				ip := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs).As16()
				failedLoginAttempts, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT {*} FROM ip_login WHERE ip = {ip}",
					Values: []any{
						sq.BytesParam("ip", ip[:]),
					},
				}, func(row *sq.Row) int {
					return row.Int("failed_login_attempts")
				})
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if failedLoginAttempts >= 3 {
					response.RequireCaptcha = true
				}
			}
		}

		if response.RequireCaptcha {
			if request.CaptchaResponse == "" {
				response.Error = "RetryWithCaptcha"
				writeResponse(w, r, response)
				return
			}
			client := &http.Client{
				Timeout: 10 * time.Second,
			}
			values := url.Values{
				"secret":   []string{nbrew.CaptchaConfig.SecretKey},
				"response": []string{request.CaptchaResponse},
				"sitekey":  []string{nbrew.CaptchaConfig.SiteKey},
			}
			ip := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs)
			if ip != (netip.Addr{}) {
				values.Set("remoteip", ip.String())
			}
			resp, err := client.Post(nbrew.CaptchaConfig.VerificationURL, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer resp.Body.Close()
			result := make(map[string]any)
			err = json.NewDecoder(resp.Body).Decode(&result)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			value := result["success"]
			if value == nil {
				b, err := json.Marshal(result)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
				} else {
					nbrew.GetLogger(r.Context()).Error(string(b))
				}
			}
			success, _ := value.(bool)
			if !success {
				response.Error = "CaptchaChallengeFailed"
				writeResponse(w, r, response)
				return
			}
		}

		if userNotFound {
			response.Error = "UserNotFound"
			writeResponse(w, r, response)
			return
		}

		err = bcrypt.CompareHashAndPassword(passwordHash, []byte(request.Password))
		if err != nil {
			response.Error = "IncorrectLoginCredentials"
			writeResponse(w, r, response)
			return
		}

		var sessionTokenBytes [8 + 16]byte
		binary.BigEndian.PutUint64(sessionTokenBytes[:8], uint64(time.Now().Unix()))
		_, err = rand.Read(sessionTokenBytes[8:])
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionTokenBytes[8:])
		copy(sessionTokenHash[:8], sessionTokenBytes[:8])
		copy(sessionTokenHash[8:], checksum[:])
		var b strings.Builder
		if nbrew.MaxMindDBReader != nil {
			addr := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs)
			if addr.IsValid() {
				var record MaxMindDBRecord
				err := nbrew.MaxMindDBReader.Lookup(net.IP(addr.AsSlice()), &record)
				if err == nil {
					country, ok := CountryCodes[record.Country.ISOCode]
					if ok {
						b.WriteString(country)
					}
				}
			}
		}
		userAgent := useragent.Parse(r.UserAgent())
		if userAgent.Name != "" {
			if userAgent.Mobile {
				if b.Len() > 0 {
					b.WriteString(" ")
				}
				b.WriteString("Mobile")
			} else if userAgent.Desktop {
				if b.Len() > 0 {
					b.WriteString(" ")
				}
				b.WriteString("Desktop")
			} else if userAgent.Tablet {
				if b.Len() > 0 {
					b.WriteString(" ")
				}
				b.WriteString("Tablet")
			}
			if userAgent.Device != "" {
				if b.Len() > 0 {
					b.WriteString(" ")
				}
				b.WriteString(userAgent.Device)
			}
			if userAgent.OS != "" {
				if b.Len() > 0 {
					b.WriteString(" ")
				}
				b.WriteString(userAgent.OS)
			}
			if b.Len() > 0 {
				b.WriteString(" ")
			}
			b.WriteString(userAgent.Name)
		}
		label := sql.NullString{
			String: b.String(),
			Valid:  b.Len() > 0,
		}
		if email != "" {
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO session (session_token_hash, user_id, label)" +
					" VALUES ({sessionTokenHash}, (SELECT user_id FROM users WHERE email = {email}), {label})",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					sq.StringParam("email", email),
					sq.Param("label", label),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.Username, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", email),
				},
			}, func(row *sq.Row) string {
				return row.String("username")
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO session (session_token_hash, user_id, label)" +
					" VALUES ({sessionTokenHash}, (SELECT user_id FROM users WHERE username = {username}), {label})",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					sq.StringParam("username", response.Username),
					sq.Param("label", label),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		response.SessionToken = strings.TrimLeft(hex.EncodeToString(sessionTokenBytes[:]), "0")
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
