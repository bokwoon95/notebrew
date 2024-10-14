package notebrew

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) invite(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Token                 string `json:"token"`
		Username              string `json:"username"`
		Email                 string `json:"email"`
		Password              string `json:"password"`
		ConfirmPassword       string `json:"confirmPassword"`
		TimezoneOffsetSeconds int    `json:"timezoneOffsetSeconds"`
		SiteName              string `json:"siteName"`
		SiteTitle             string `json:"siteTitle"`
		SiteTagline           string `json:"siteTagline"`
		SiteDescription       string `json:"siteDescription"`
	}
	type Response struct {
		Token                 string     `json:"token"`
		ValidateEmail         bool       `json:"validateEmail"`
		Username              string     `json:"username"`
		Email                 string     `json:"email"`
		TimezoneOffsetSeconds int        `json:"timezoneOffsetSeconds"`
		SiteName              string     `json:"siteName"`
		SiteTitle             string     `json:"siteTitle"`
		SiteTagline           string     `json:"siteTagline"`
		SiteDescription       string     `json:"siteDescription"`
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
			funcMap := map[string]any{
				"join":       path.Join,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
			}
			tmpl, err := template.New("invite.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/invite.html")
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
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		if !user.UserID.IsZero() {
			response.Error = "AlreadyAuthenticated"
			writeResponse(w, r, response)
			return
		}
		response.Token = r.Form.Get("token")
		if response.Token == "" {
			response.Error = "MissingInviteToken"
			writeResponse(w, r, response)
			return
		}
		if len(response.Token) > 48 {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		inviteTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", response.Token))
		if err != nil {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		checksum := blake2b.Sum256(inviteTokenBytes[8:])
		var inviteTokenHash [8 + blake2b.Size256]byte
		copy(inviteTokenHash[:8], inviteTokenBytes[:8])
		copy(inviteTokenHash[8:], checksum[:])
		validateEmail, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM invite WHERE invite_token_hash = {inviteTokenHash}",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("email IS NOT NULL")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				response.Error = "InvalidInviteToken"
				writeResponse(w, r, response)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.ValidateEmail = validateEmail
		writeResponse(w, r, response)
	case "POST":
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
				var query string
				if response.Token != "" {
					query = "?token=" + url.QueryEscape(response.Token)
				}
				http.Redirect(w, r, "/users/invite/"+query, http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "invite",
				},
				"username": response.Username,
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
			request.Token = r.Form.Get("token")
			request.Username = r.Form.Get("username")
			request.Email = r.Form.Get("email")
			request.Password = r.Form.Get("password")
			request.ConfirmPassword = r.Form.Get("confirmPassword")
			if s := r.Form.Get("timezoneOffsetSeconds"); s != "" {
				timezoneOffsetSeconds, err := strconv.Atoi(s)
				if err != nil {
					nbrew.BadRequest(w, r, fmt.Errorf("timezoneOffsetSeconds: %s is not an integer", s))
					return
				}
				request.TimezoneOffsetSeconds = timezoneOffsetSeconds
			}
			request.SiteName = r.Form.Get("siteName")
			request.SiteTitle = r.Form.Get("siteTitle")
			request.SiteTagline = r.Form.Get("siteTagline")
			request.SiteDescription = r.Form.Get("siteDescription")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Token:                 request.Token,
			Username:              request.Username,
			Email:                 request.Email,
			TimezoneOffsetSeconds: request.TimezoneOffsetSeconds,
			SiteName:              request.SiteName,
			SiteTitle:             request.SiteTitle,
			SiteTagline:           request.SiteTagline,
			SiteDescription:       request.SiteDescription,
			FormErrors:            url.Values{},
		}
		// token
		if response.Token == "" {
			response.Error = "MissingInviteToken"
			writeResponse(w, r, response)
			return
		}
		if len(response.Token) > 48 {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		inviteTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", response.Token))
		if err != nil {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		checksum := blake2b.Sum256(inviteTokenBytes[8:])
		var inviteTokenHash [8 + blake2b.Size256]byte
		copy(inviteTokenHash[:8], inviteTokenBytes[:8])
		copy(inviteTokenHash[8:], checksum[:])
		result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM invite WHERE invite_token_hash = {inviteTokenHash}",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			},
		}, func(row *sq.Row) (result struct {
			Email        sql.NullString
			SiteLimit    sql.NullInt64
			StorageLimit sql.NullInt64
			UserFlags    sql.NullString
		}) {
			result.Email = row.NullString("email")
			result.SiteLimit = row.NullInt64("site_limit")
			result.StorageLimit = row.NullInt64("storage_limit")
			result.UserFlags = row.NullString("user_flags")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				response.Error = "InvalidInviteToken"
				writeResponse(w, r, response)
				return
			}
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		// username
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
		if !response.FormErrors.Has("username") {
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
		// email
		if response.Email == "" {
			response.FormErrors.Add("email", "required")
		} else {
			_, err := mail.ParseAddress(response.Email)
			if err != nil {
				response.FormErrors.Add("email", "invalid email address")
			}
		}
		if !response.FormErrors.Has("email") {
			if result.Email.Valid {
				response.ValidateEmail = true
				if result.Email.String != response.Email {
					response.FormErrors.Add("email", "email is incorrect")
				}
			}
		}
		if !response.FormErrors.Has("email") {
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
		// password
		if request.Password == "" {
			response.FormErrors.Add("password", "required")
		} else {
			if utf8.RuneCountInString(request.Password) < 8 {
				response.FormErrors.Add("password", "password must be at least 8 characters")
			}
			if _, ok := commonPasswords[request.Password]; ok {
				response.FormErrors.Add("password", "password is too common")
			}
		}
		// confirmPassword
		if !response.FormErrors.Has("password") {
			if request.ConfirmPassword == "" {
				response.FormErrors.Add("confirmPassword", "required")
			} else {
				if request.Password != request.ConfirmPassword {
					response.FormErrors.Add("confirmPassword", "password does not match")
				}
			}
		}
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if response.SiteName != "" {
			if slices.Contains(ReservedSubdomains, response.SiteName) {
				response.FormErrors.Add("siteName", "unavailable")
			} else {
				for _, char := range response.SiteName {
					if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
						response.FormErrors.Add("siteName", fmt.Sprintf("cannot include character %q", string(char)))
						break
					}
				}
				if len(response.SiteName) > 30 {
					response.FormErrors.Add("siteName", "cannot exceed 30 characters")
				}
			}
			if !response.FormErrors.Has("siteName") {
				exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
					Values: []any{
						sq.StringParam("siteName", response.SiteName),
					},
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if exists {
					response.FormErrors.Add("siteName", "site name already in use")
				}
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
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
			Format:  "DELETE FROM invite WHERE invite_token_hash = {inviteTokenHash}",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO users (user_id, username, email, password_hash, timezone_offset_seconds, site_limit, storage_limit, user_flags)" +
				" VALUES ({userID}, {username}, {email}, {passwordHash}, {timezoneOffsetSeconds}, {siteLimit}, {storageLimit}, {userFlags})",
			Values: []any{
				sq.UUIDParam("userID", NewID()),
				sq.StringParam("username", response.Username),
				sq.StringParam("email", response.Email),
				sq.StringParam("passwordHash", string(passwordHash)),
				sq.IntParam("timezoneOffsetSeconds", response.TimezoneOffsetSeconds),
				sq.Param("siteLimit", result.SiteLimit),
				sq.Param("storageLimit", result.StorageLimit),
				sq.Param("userFlags", result.UserFlags),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if response.SiteName != "" {
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO site (site_id, site_name)" +
					" VALUES ({siteID}, {siteName})",
				Values: []any{
					sq.UUIDParam("siteID", NewID()),
					sq.StringParam("siteName", response.SiteName),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO site_user (site_id, user_id)" +
					" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
				Values: []any{
					sq.StringParam("siteName", response.SiteName),
					sq.StringParam("username", response.Username),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO site_owner (site_id, user_id)" +
					" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
				Values: []any{
					sq.StringParam("siteName", response.SiteName),
					sq.StringParam("username", response.Username),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		err = tx.Commit()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if response.SiteName == "" {
			writeResponse(w, r, response)
			return
		}
		sitePrefix := "@" + response.SiteName
		err = nbrew.FS.Mkdir(sitePrefix, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		dirs := []string{
			"notes",
			"pages",
			"posts",
			"output",
			"output/posts",
			"output/themes",
			"imports",
			"exports",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		sign := "+"
		seconds := response.TimezoneOffsetSeconds
		if response.TimezoneOffsetSeconds < 0 {
			sign = "-"
			seconds = -response.TimezoneOffsetSeconds
		}
		hours := seconds / 3600
		minutes := (seconds % 3600) / 60
		siteConfig := SiteConfig{
			LanguageCode:   "en",
			Title:          response.SiteTitle,
			Tagline:        response.SiteTagline,
			Emoji:          "☕️",
			Favicon:        "",
			CodeStyle:      "onedark",
			TimezoneOffset: fmt.Sprintf("%s%02d:%02d", sign, hours, minutes),
			Description:    response.SiteDescription,
			NavigationLinks: []NavigationLink{{
				Name: "Home",
				URL:  "/",
			}, {
				Name: "Posts",
				URL:  "/posts/",
			}},
		}
		b, err := json.MarshalIndent(&siteConfig, "", "  ")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
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
			b, err := fs.ReadFile(RuntimeFS, "embed/postlist.json")
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/postlist.json"), 0644)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			b, err := fs.ReadFile(RuntimeFS, "embed/index.html")
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			creationTime := time.Now()
			err = siteGen.GeneratePage(groupctx, "pages/index.html", string(b), creationTime, creationTime)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			b, err := fs.ReadFile(RuntimeFS, "embed/404.html")
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			creationTime := time.Now()
			err = siteGen.GeneratePage(groupctx, "pages/404.html", string(b), creationTime, creationTime)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			b, err := fs.ReadFile(RuntimeFS, "embed/post.html")
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/post.html"), 0644)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			b, err := fs.ReadFile(RuntimeFS, "embed/postlist.html")
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/postlist.html"), 0644)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			tmpl, err := siteGen.PostListTemplate(context.Background(), "")
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
			if err != nil {
				nbrew.GetLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if strings.Contains(response.SiteName, ".") && nbrew.Port == 443 {
			certConfig := certmagic.NewDefault()
			certConfig.Storage = nbrew.CertStorage
			err := certConfig.ObtainCertSync(r.Context(), response.SiteName)
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
