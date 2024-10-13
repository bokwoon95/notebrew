package notebrew

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) profile(w http.ResponseWriter, r *http.Request, user User) {
	type Site struct {
		SiteID      ID     `json:"siteID"`
		SiteName    string `json:"siteName"`
		StorageUsed int64  `json:"storageUsed"`
	}
	type Session struct {
		sessionTokenHash   []byte    `json:"-"`
		SessionTokenPrefix string    `json:"sessionTokenPrefix"`
		CreationTime       time.Time `json:"creationTime"`
		Label              string    `json:"label"`
		Current            bool      `json:"current"`
	}
	type Response struct {
		UserID                ID              `json:"userID"`
		Username              string          `json:"username"`
		Email                 string          `json:"email"`
		TimezoneOffsetSeconds int             `json:"timezoneOffsetSeconds"`
		DisableReason         string          `json:"disableReason"`
		SiteLimit             int64           `json:"siteLimit"`
		StorageLimit          int64           `json:"storageLimit"`
		UserFlags             map[string]bool `json:"userFlags"`
		StorageUsed           int64           `json:"storageUsed"`
		Sites                 []Site          `json:"sites"`
		Sessions              []Session       `json:"sessions"`
		PostRedirectGet       map[string]any  `json:"postRedirectGet"`
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.MethodNotAllowed(w, r)
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
		referer := nbrew.GetReferer(r)
		funcMap := map[string]any{
			"join":                  path.Join,
			"dir":                   path.Dir,
			"base":                  path.Base,
			"ext":                   path.Ext,
			"hasPrefix":             strings.HasPrefix,
			"hasSuffix":             strings.HasSuffix,
			"trimPrefix":            strings.TrimPrefix,
			"trimSuffix":            strings.TrimSuffix,
			"humanReadableFileSize": HumanReadableFileSize,
			"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
			"referer":               func() string { return referer },
			"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
			"float64ToInt64":        func(n float64) int64 { return int64(n) },
			"formatTime": func(t time.Time, layout string, offset int) string {
				return t.In(time.FixedZone("", offset)).Format(layout)
			},
			"formatTimezone": func(offset int) string {
				sign := "+"
				seconds := offset
				if offset < 0 {
					sign = "-"
					seconds = -offset
				}
				hours := seconds / 3600
				minutes := (seconds % 3600) / 60
				return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
			},
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"sitePrefix": func(siteName string) string {
				if siteName == "" {
					return ""
				}
				if strings.Contains(siteName, ".") {
					return siteName
				}
				return "@" + siteName
			},
		}
		tmpl, err := template.New("profile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/profile.html")
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
	response.Email = user.Email
	response.TimezoneOffsetSeconds = user.TimezoneOffsetSeconds
	response.DisableReason = user.DisableReason
	response.SiteLimit = user.SiteLimit
	response.StorageLimit = user.StorageLimit
	response.UserFlags = user.UserFlags
	group, groupctx := errgroup.WithContext(r.Context())
	group.Go(func() (err error) {
		defer stacktrace.RecoverPanic(&err)
		sites, err := sq.FetchAll(groupctx, nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "SELECT {*}" +
				" FROM site" +
				" JOIN site_owner ON site_owner.site_id = site.site_id" +
				" WHERE site_owner.user_id = {userID}",
			Values: []any{
				sq.UUIDParam("userID", user.UserID),
			},
		}, func(row *sq.Row) Site {
			return Site{
				SiteID:      row.UUID("site.site_id"),
				SiteName:    row.String("site.site_name"),
				StorageUsed: row.Int64("site.storage_used"),
			}
		})
		if err != nil {
			return err
		}
		response.Sites = sites
		for _, site := range response.Sites {
			response.StorageUsed += site.StorageUsed
		}
		return nil
	})
	group.Go(func() (err error) {
		defer stacktrace.RecoverPanic(&err)
		sessions, err := sq.FetchAll(groupctx, nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM session WHERE user_id = {userID}",
			Values: []any{
				sq.UUIDParam("userID", user.UserID),
			},
		}, func(row *sq.Row) Session {
			return Session{
				sessionTokenHash: row.Bytes(nil, "session_token_hash"),
				Label:            row.String("label"),
			}
		})
		if err != nil {
			return err
		}
		var currentSessionTokenHash []byte
		header := r.Header.Get("Authorization")
		if header != "" {
			if strings.HasPrefix(header, "Bearer ") {
				currentSessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", strings.TrimPrefix(header, "Bearer ")))
				if err == nil && len(currentSessionTokenBytes) == 24 {
					currentSessionTokenHash = make([]byte, 8+blake2b.Size256)
					checksum := blake2b.Sum256(currentSessionTokenBytes[8:])
					copy(currentSessionTokenHash[:8], currentSessionTokenBytes[:8])
					copy(currentSessionTokenHash[8:], checksum[:])
				}
			}
		} else {
			cookie, _ := r.Cookie("session")
			if cookie != nil {
				currentSessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
				if err == nil && len(currentSessionTokenBytes) == 24 {
					currentSessionTokenHash = make([]byte, 8+blake2b.Size256)
					checksum := blake2b.Sum256(currentSessionTokenBytes[8:])
					copy(currentSessionTokenHash[:8], currentSessionTokenBytes[:8])
					copy(currentSessionTokenHash[8:], checksum[:])
				}
			}
		}
		for i := range sessions {
			sessionTokenHash := sessions[i].sessionTokenHash
			if len(sessionTokenHash) != 40 {
				continue
			}
			sessions[i].SessionTokenPrefix = strings.TrimLeft(hex.EncodeToString(sessionTokenHash[:8]), "0")
			sessions[i].CreationTime = time.Unix(int64(binary.BigEndian.Uint64(sessionTokenHash[:8])), 0).UTC()
			sessions[i].Current = bytes.Equal(sessionTokenHash, currentSessionTokenHash)
		}
		response.Sessions = sessions
		return nil
	})
	err = group.Wait()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	writeResponse(w, r, response)
}
