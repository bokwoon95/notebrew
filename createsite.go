package notebrew

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/caddyserver/certmagic"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) createsite(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		SiteName        string `json:"siteName"`
		SiteTitle       string `json:"siteTitle"`
		SiteTagline     string `json:"siteTagline"`
		SiteDescription string `json:"siteDescription"`
	}
	type Response struct {
		CMSDomain            string          `json:"cmsDomain"`
		ContentDomain        string          `json:"contentDomain"`
		IP4                  netip.Addr      `json:"ip4"`
		ValidateCustomDomain bool            `json:"validateCustomDomain"`
		UserID               ID              `json:"userID"`
		Username             string          `json:"username"`
		DisableReason        string          `json:"disableReason"`
		SiteLimit            int64           `json:"siteLimit"`
		UserFlags            map[string]bool `json:"userFlags"`
		UserSiteNames        []string        `json:"userSiteNames"`
		SiteName             string          `json:"siteName"`
		SiteTitle            string          `json:"siteTitle"`
		SiteTagline          string          `json:"siteTagline"`
		SiteDescription      string          `json:"siteDescription"`
		Error                string          `json:"error"`
		FormErrors           url.Values      `json:"formErrors"`
	}

	getUserSiteInfo := func(username string) (userSiteNames []string, maxSitesReached bool, err error) {
		if nbrew.DB == nil {
			return nil, false, nil
		}
		userSiteNames, err = sq.FetchAll(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "SELECT {*}" +
				" FROM site" +
				" JOIN site_owner ON site_owner.site_id = site.site_id" +
				" JOIN users ON users.user_id = site_owner.user_id" +
				" WHERE users.username = {username}",
			Values: []any{
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) string {
			return row.String("site.site_name")
		})
		if err != nil {
			return nil, false, err
		}
		n := 0
		for _, userSiteName := range userSiteNames {
			if userSiteName == "" {
				continue
			}
			userSiteNames[n] = userSiteName
			n++
		}
		userSiteNames = userSiteNames[:n]
		return userSiteNames, user.SiteLimit >= 0 && len(userSiteNames) >= int(user.SiteLimit), nil
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
				"maxSites":   func() int { return int(user.SiteLimit) },
			}
			tmpl, err := template.New("createsite.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createsite.html")
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
		response.ContentDomain = nbrew.ContentDomain
		response.ValidateCustomDomain = nbrew.Port == 443
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SiteLimit = user.SiteLimit
		response.UserFlags = user.UserFlags
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		userSiteNames, maxSitesReached, err := getUserSiteInfo(user.Username)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.UserSiteNames = userSiteNames
		if maxSitesReached {
			response.Error = "MaxSitesReached"
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
				http.Redirect(w, r, "/files/createsite/", http.StatusFound)
				return
			}
			sitePrefix := response.SiteName
			if !strings.Contains(response.SiteName, ".") {
				sitePrefix = "@" + response.SiteName
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":       "createsite",
					"sitePrefix": sitePrefix,
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
			request.SiteTitle = r.Form.Get("siteTitle")
			request.SiteTagline = r.Form.Get("siteTagline")
			request.SiteDescription = r.Form.Get("siteDescription")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		var err error
		response := Response{
			SiteName:        request.SiteName,
			SiteTitle:       request.SiteTitle,
			SiteTagline:     request.SiteTagline,
			SiteDescription: request.SiteDescription,
			FormErrors:      url.Values{},
		}
		userSiteNames, maxSitesReached, err := getUserSiteInfo(user.Username)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.UserSiteNames = userSiteNames
		if maxSitesReached {
			response.Error = "MaxSitesReached"
			writeResponse(w, r, response)
			return
		}

		if response.SiteName == "" {
			response.FormErrors.Add("siteName", "required")
		} else if slices.Contains(ReservedSubdomains, response.SiteName) {
			response.FormErrors.Add("siteName", "unavailable")
		} else {
			hasForbiddenCharacters := false
			digitCount := 0
			for _, char := range response.SiteName {
				if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '.' {
					hasForbiddenCharacters = true
				}
				if char >= '0' && char <= '9' {
					digitCount++
				}
			}
			if hasForbiddenCharacters {
				response.FormErrors.Add("siteName", "only lowercase letters, numbers, hyphen and dot allowed")
			}
			if len(response.SiteName) > 30 {
				response.FormErrors.Add("siteName", "cannot exceed 30 characters")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		var sitePrefix string
		if strings.Contains(response.SiteName, ".") {
			if user.UserFlags["NoCustomDomain"] {
				response.FormErrors.Add("siteName", "custom domain not allowed")
				response.Error = "CustomDomainNotAllowed"
				writeResponse(w, r, response)
				return
			}
			sitePrefix = response.SiteName
			if nbrew.Port == 443 {
				ips, err := net.DefaultResolver.LookupIPAddr(r.Context(), response.SiteName)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				matched := false
				for _, ip := range ips {
					ip, ok := netip.AddrFromSlice(ip.IP)
					if !ok {
						continue
					}
					if ip.Is4() && ip == nbrew.IP4 || ip.Is6() && ip == nbrew.IP6 {
						matched = true
						break
					}
				}
				if !matched {
					response.FormErrors.Add("siteName", fmt.Sprintf("please add a CNAME DNS record for this domain to point at %s", "www."+nbrew.ContentDomain))
					response.Error = "DomainNotMatched"
					writeResponse(w, r, response)
					return
				}
			}
		} else if response.SiteName != "" {
			sitePrefix = "@" + response.SiteName
		}
		if nbrew.DB != nil {
			tx, err := nbrew.DB.Begin()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer tx.Rollback()
			siteID := NewID()
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
				Values: []any{
					sq.UUIDParam("siteID", siteID),
					sq.StringParam("siteName", request.SiteName),
				},
			})
			if err != nil {
				if nbrew.ErrorCode != nil {
					errorCode := nbrew.ErrorCode(err)
					if IsKeyViolation(nbrew.Dialect, errorCode) {
						response.FormErrors.Add("siteName", "unavailable")
						response.Error = "FormErrorsPresent"
						writeResponse(w, r, response)
						return
					}
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO site_owner (site_id, user_id)" +
					" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
					sq.StringParam("username", user.Username),
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
					sq.StringParam("siteName", request.SiteName),
					sq.StringParam("username", user.Username),
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
		seconds := user.TimezoneOffsetSeconds
		sign := "+"
		if seconds < 0 {
			seconds = -seconds
			sign = "-"
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
