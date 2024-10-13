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

func (nbrew *Notebrew) cancelexport(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type ExportJob struct {
		ExportJobID    ID        `json:"exportJobID"`
		TgzFileName    string    `json:"tgzFileName"`
		StartTime      time.Time `json:"startTime"`
		TotalBytes     int64     `json:"totalBytes"`
		ProcessedBytes int64     `json:"processedBytes"`
	}
	type Request struct {
		ExportJobIDs []ID `json:"exportJobIDs"`
	}
	type Response struct {
		ContentBaseURL string      `json:"contentBaseURL"`
		CDNDomain      string      `json:"cdnDomain"`
		IsDatabaseFS   bool        `json:"isDatabaseFS"`
		SitePrefix     string      `json:"sitePrefix"`
		UserID         ID          `json:"userID"`
		Username       string      `json:"username"`
		DisableReason  string      `json:"disableReason"`
		ExportJobs     []ExportJob `json:"exportJobs"`
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
			tmpl, err := template.New("cancelexport.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/cancelexport.html")
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
		var exportJobIDs []ID
		for _, s := range r.Form["exportJobID"] {
			exportJobID, err := ParseID(s)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
			exportJobIDs = append(exportJobIDs, exportJobID)
		}
		response.ExportJobs = make([]ExportJob, len(exportJobIDs))
		group, groupctx := errgroup.WithContext(r.Context())
		for i, exportJobID := range exportJobIDs {
			i, exportJobID := i, exportJobID
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				exportJob, err := sq.FetchOne(groupctx, nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT {*} FROM export_job WHERE export_job_id = {exportJobID}",
					Values: []any{
						sq.UUIDParam("exportJobID", exportJobID),
					},
				}, func(row *sq.Row) ExportJob {
					return ExportJob{
						ExportJobID:    row.UUID("export_job_id"),
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
				response.ExportJobs[i] = exportJob
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
		for _, exportJob := range response.ExportJobs {
			if exportJob.ExportJobID.IsZero() {
				continue
			}
			response.ExportJobs[n] = exportJob
			n++
		}
		response.ExportJobs = response.ExportJobs[:n]
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
					"from":         "cancelexport",
					"numCanceled":  len(response.ExportJobs),
					"cancelErrors": response.CancelErrors,
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "exports")+"/", http.StatusFound)
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
			for _, s := range r.Form["exportJobID"] {
				exportJobID, err := ParseID(s)
				if err != nil {
					nbrew.BadRequest(w, r, err)
					return
				}
				request.ExportJobIDs = append(request.ExportJobIDs, exportJobID)
			}
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		var response Response
		response.ExportJobs = make([]ExportJob, len(request.ExportJobIDs))
		response.CancelErrors = make([]string, len(request.ExportJobIDs))
		var waitGroup sync.WaitGroup
		for i, exportJobID := range request.ExportJobIDs {
			i, exportJobID := i, exportJobID
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
					Format:  "DELETE FROM export_job WHERE export_job_id = {exportJobID}",
					Values: []any{
						sq.UUIDParam("exportJobID", exportJobID),
					},
				})
				if err != nil {
					response.CancelErrors[i] = err.Error()
				} else if result.RowsAffected != 0 {
					response.ExportJobs[i] = ExportJob{ExportJobID: exportJobID}
				}
			}()
		}
		waitGroup.Wait()
		n := 0
		for _, exportJob := range response.ExportJobs {
			if exportJob.ExportJobID.IsZero() {
				continue
			}
			response.ExportJobs[n] = exportJob
			n++
		}
		response.ExportJobs = response.ExportJobs[:n]
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
