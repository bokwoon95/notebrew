package notebrew

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/mileusna/useragent"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) createsession(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Label string `json:"label"`
	}
	type Response struct {
		ContentBaseURL string `json:"contentBaseURL"`
		SitePrefix     string `json:"sitePrefix"`
		UserID         ID     `json:"userID"`
		Username       string `json:"username"`
		DisableReason  string `json:"disableReason"`
		Label          string `json:"label"`
		SessionToken   string `json:"sessionToken"`
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
			tmpl, err := template.New("createsession.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createsession.html")
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
			err := nbrew.SetFlashSession(w, r, &response)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/users/createsession/", http.StatusFound)
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
			request.Label = r.Form.Get("label")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Label: request.Label,
		}
		if response.Label == "" {
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
			response.Label = b.String()
		}
		var sessionTokenBytes [8 + 16]byte
		binary.BigEndian.PutUint64(sessionTokenBytes[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(sessionTokenBytes[8:])
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionTokenBytes[8:])
		copy(sessionTokenHash[:8], sessionTokenBytes[:8])
		copy(sessionTokenHash[8:], checksum[:])
		_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO session (session_token_hash, user_id, label)" +
				" VALUES ({sessionTokenHash}, {userID}, {label})",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				sq.UUIDParam("userID", user.UserID),
				sq.Param("label", response.Label),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.SessionToken = strings.TrimLeft(hex.EncodeToString(sessionTokenBytes[:]), "0")
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
