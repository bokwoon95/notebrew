package notebrew

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) deletesession(w http.ResponseWriter, r *http.Request, user User) {
	type Session struct {
		sessionTokenHash   []byte    `json:"-"`
		SessionTokenPrefix string    `json:"sessionTokenPrefix"`
		CreationTime       time.Time `json:"creationTime"`
		Label              string    `json:"label"`
	}
	type Request struct {
		SessionTokenPrefixes []string `json:"sessionTokenPrefixes"`
	}
	type Response struct {
		UserID                ID        `json:"userID"`
		Username              string    `json:"username"`
		TimezoneOffsetSeconds int       `json:"timezoneOffsetSeconds"`
		DisableReason         string    `json:"disableReason"`
		Sessions              []Session `json:"sessions"`
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
				"formatTime": func(t time.Time, layout string, offset int) string {
					return t.In(time.FixedZone("", offset)).Format(layout)
				},
			}
			tmpl, err := template.New("deletesession.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/deletesession.html")
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
		response.TimezoneOffsetSeconds = user.TimezoneOffsetSeconds
		response.DisableReason = user.DisableReason
		seen := make(map[string]bool)
		sessionTokenPrefixes := make([]string, 0, len(r.Form["sessionTokenPrefix"]))
		for _, sessionTokenPrefix := range r.Form["sessionTokenPrefix"] {
			if len(sessionTokenPrefix) > 16 {
				continue
			}
			if seen[sessionTokenPrefix] {
				continue
			}
			seen[sessionTokenPrefix] = true
			sessionTokenPrefixes = append(sessionTokenPrefixes, sessionTokenPrefix)
		}
		slices.Sort(sessionTokenPrefixes)
		sessionTokenHashes := make([][8 + blake2b.Size256]byte, 0, len(sessionTokenPrefixes)*2)
		for _, sessionTokenPrefix := range sessionTokenPrefixes {
			sessionTokenPrefixBytes, err := hex.DecodeString(fmt.Sprintf("%016s", sessionTokenPrefix))
			if err != nil {
				continue
			}
			var lowerBound, upperBound [8 + blake2b.Size256]byte
			for i := 0; i < len(upperBound); i++ {
				upperBound[i] = 0xff
			}
			copy(lowerBound[:], sessionTokenPrefixBytes)
			copy(upperBound[:], sessionTokenPrefixBytes)
			sessionTokenHashes = append(sessionTokenHashes, lowerBound, upperBound)
		}
		for i := 0; i+1 < len(sessionTokenHashes); i += 2 {
			lowerBound, upperBound := sessionTokenHashes[i], sessionTokenHashes[i+1]
			sessions, err := sq.FetchAll(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM session" +
					" WHERE user_id = {userID}" +
					" AND session_token_hash >= {lowerBound}" +
					" AND session_token_hash <= {upperBound}",
				Values: []any{
					sq.UUIDParam("userID", user.UserID),
					sq.BytesParam("lowerBound", lowerBound[:]),
					sq.BytesParam("upperBound", upperBound[:]),
				},
			}, func(row *sq.Row) Session {
				return Session{
					sessionTokenHash: row.Bytes(nil, "session_token_hash"),
					Label:            row.String("label"),
				}
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.Sessions = append(response.Sessions, sessions...)
		}
		n := 0
		for _, session := range response.Sessions {
			if len(session.sessionTokenHash) != 40 {
				continue
			}
			session.SessionTokenPrefix = strings.TrimLeft(hex.EncodeToString(session.sessionTokenHash[:8]), "0")
			session.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(session.sessionTokenHash[:8])), 0).UTC()
			response.Sessions[n] = session
			n++
		}
		response.Sessions = response.Sessions[:n]
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
					"from": "deletesession",
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
			request.SessionTokenPrefixes = r.Form["sessionTokenPrefix"]
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{}
		seen := make(map[string]bool)
		sessionTokenPrefixes := make([]string, 0, len(request.SessionTokenPrefixes))
		for _, sessionTokenPrefix := range request.SessionTokenPrefixes {
			if len(sessionTokenPrefix) > 16 {
				continue
			}
			if seen[sessionTokenPrefix] {
				continue
			}
			seen[sessionTokenPrefix] = true
			sessionTokenPrefixes = append(sessionTokenPrefixes, sessionTokenPrefix)
		}
		slices.Sort(sessionTokenPrefixes)
		sessionTokenHashes := make([][8 + blake2b.Size256]byte, 0, len(sessionTokenPrefixes)*2)
		for _, sessionTokenPrefix := range sessionTokenPrefixes {
			sessionTokenPrefixBytes, err := hex.DecodeString(fmt.Sprintf("%016s", sessionTokenPrefix))
			if err != nil {
				continue
			}
			var lowerBound, upperBound [8 + blake2b.Size256]byte
			for i := 0; i < len(upperBound); i++ {
				upperBound[i] = 0xff
			}
			copy(lowerBound[:], sessionTokenPrefixBytes)
			copy(upperBound[:], sessionTokenPrefixBytes)
			sessionTokenHashes = append(sessionTokenHashes, lowerBound, upperBound)
		}
		for i := 0; i+1 < len(sessionTokenHashes); i += 2 {
			var err error
			var sessions []Session
			lowerBound, upperBound := sessionTokenHashes[i], sessionTokenHashes[i+1]
			if nbrew.Dialect == "sqlite" || nbrew.Dialect == "postgres" {
				sessions, err = sq.FetchAll(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "DELETE FROM session" +
						" WHERE user_id = {userID}" +
						" AND session_token_hash >= {lowerBound}" +
						" AND session_token_hash <= {upperBound}" +
						" RETURNING {*}",
					Values: []any{
						sq.UUIDParam("userID", user.UserID),
						sq.BytesParam("lowerBound", lowerBound[:]),
						sq.BytesParam("upperBound", upperBound[:]),
					},
				}, func(row *sq.Row) Session {
					return Session{
						sessionTokenHash: row.Bytes(nil, "session_token_hash"),
						Label:            row.String("label"),
					}
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.Sessions = append(response.Sessions, sessions...)
			} else {
				sessions, err := sq.FetchAll(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "SELECT {*}" +
						" FROM session" +
						" WHERE user_id = {userID}" +
						" AND session_token_hash >= {lowerBound}" +
						" AND session_token_hash <= {upperBound}",
					Values: []any{
						sq.UUIDParam("userID", user.UserID),
						sq.BytesParam("lowerBound", lowerBound[:]),
						sq.BytesParam("upperBound", upperBound[:]),
					},
				}, func(row *sq.Row) Session {
					return Session{
						sessionTokenHash: row.Bytes(nil, "session_token_hash"),
						Label:            row.String("label"),
					}
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.Sessions = append(response.Sessions, sessions...)
				_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "DELETE FROM session" +
						" WHERE user_id = {userID}" +
						" AND session_token_hash >= {lowerBound}" +
						" AND session_token_hash <= {upperBound}",
					Values: []any{
						sq.UUIDParam("userID", user.UserID),
						sq.BytesParam("lowerBound", lowerBound[:]),
						sq.BytesParam("upperBound", upperBound[:]),
					},
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
