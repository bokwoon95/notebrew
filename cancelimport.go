package notebrew

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) cancelimport(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type ImportJob struct {
		ImportJobID    ID        `json:"importJobID"`
		TgzFileName    string    `json:"tgzFileName"`
		StartTime      time.Time `json:"startTime"`
		TotalBytes     int64     `json:"totalBytes"`
		ProcessedBytes int64     `json:"processedBytes"`
	}
	type Request struct {
		ImportJobIDs []ID `json:"importJobIDs"`
	}
	type Response struct {
		ContentBaseURL string      `json:"contentBaseURL"`
		CDNDomain      string      `json:"cdnDomain"`
		IsDatabaseFS   bool        `json:"isDatabaseFS"`
		SitePrefix     string      `json:"sitePrefix"`
		UserID         ID          `json:"userID"`
		Username       string      `json:"username"`
		DisableReason  string      `json:"disableReason"`
		ImportJobs     []ImportJob `json:"importJobs"`
		CancelErrors   []string    `json:"cancelErrors"`
	}
	if nbrew.DB == nil {
		nbrew.NotFound(w, r)
		return
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
				"join":                  path.Join,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
			}
			tmpl, err := template.New("cancelimport.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/cancelimport.html")
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
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.CDNDomain = nbrew.CDNDomain
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			response.IsDatabaseFS = v.As(&DatabaseFS{})
		}
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		var importJobIDs []ID
		for _, s := range r.Form["importJobID"] {
			importJobID, err := ParseID(s)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
			importJobIDs = append(importJobIDs, importJobID)
		}
		response.ImportJobs = make([]ImportJob, len(importJobIDs))
		group, groupctx := errgroup.WithContext(r.Context())
		for i, importJobID := range importJobIDs {
			i, importJobID := i, importJobID
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				importJob, err := sq.FetchOne(groupctx, nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT {*} FROM import_job WHERE import_job_id = {importJobID}",
					Values: []any{
						sq.UUIDParam("importJobID", importJobID),
					},
				}, func(row *sq.Row) ImportJob {
					return ImportJob{
						ImportJobID:    row.UUID("import_job_id"),
						TgzFileName:    row.String("tgz_file_name"),
						StartTime:      row.Time("start_time"),
						TotalBytes:     row.Int64("total_bytes"),
						ProcessedBytes: row.Int64("processed_bytes"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return stacktrace.New(err)
				}
				response.ImportJobs[i] = importJob
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		n := 0
		for _, importJob := range response.ImportJobs {
			if importJob.ImportJobID.IsZero() {
				continue
			}
			response.ImportJobs[n] = importJob
			n++
		}
		response.ImportJobs = response.ImportJobs[:n]
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
					"from":         "cancelimport",
					"numCanceled":  len(response.ImportJobs),
					"cancelErrors": response.CancelErrors,
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "imports")+"/", http.StatusFound)
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
			for _, s := range r.Form["importJobID"] {
				importJobID, err := ParseID(s)
				if err != nil {
					nbrew.BadRequest(w, r, err)
					return
				}
				request.ImportJobIDs = append(request.ImportJobIDs, importJobID)
			}
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		var response Response
		response.ImportJobs = make([]ImportJob, len(request.ImportJobIDs))
		response.CancelErrors = make([]string, len(request.ImportJobIDs))
		var waitGroup sync.WaitGroup
		for i, importJobID := range request.ImportJobIDs {
			i, importJobID := i, importJobID
			waitGroup.Add(1)
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
					}
				}()
				defer waitGroup.Done()
				result, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "DELETE FROM import_job WHERE import_job_id = {importJobID}",
					Values: []any{
						sq.UUIDParam("importJobID", importJobID),
					},
				})
				if err != nil {
					response.CancelErrors[i] = err.Error()
				} else if result.RowsAffected != 0 {
					response.ImportJobs[i] = ImportJob{ImportJobID: importJobID}
				}
			}()
		}
		waitGroup.Wait()
		n := 0
		for _, importJob := range response.ImportJobs {
			if importJob.ImportJobID.IsZero() {
				continue
			}
			response.ImportJobs[n] = importJob
			n++
		}
		response.ImportJobs = response.ImportJobs[:n]
		n = 0
		for _, cancelError := range response.CancelErrors {
			if cancelError == "" {
				continue
			}
			response.CancelErrors[n] = cancelError
			n++
		}
		response.CancelErrors = response.CancelErrors[:n]
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
