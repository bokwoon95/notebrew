package notebrew

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

type exportAction int

const (
	exportFiles       exportAction = 1 << 0
	exportDirectories exportAction = 1 << 1
)

func (nbrew *Notebrew) export(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		Size         int64     `json:"size"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Request struct {
		Parent     string   `json:"parent"`
		Names      []string `json:"names"`
		OutputName string   `json:"outputName"`
	}
	type Response struct {
		ContentBaseURL string     `json:"contentBaseURL"`
		CDNDomain      string     `json:"cdnDomain"`
		IsDatabaseFS   bool       `json:"isDatabaseFS"`
		SitePrefix     string     `json:"sitePrefix"`
		UserID         ID         `json:"userID"`
		Username       string     `json:"username"`
		DisableReason  string     `json:"disableReason"`
		Parent         string     `json:"parent"`
		Names          []string   `json:"names"`
		OutputName     string     `json:"outputName"`
		ExportParent   bool       `json:"exportParent"`
		TotalBytes     int64      `json:"totalBytes"`
		Files          []File     `json:"files"`
		Error          string     `json:"error"`
		FormErrors     url.Values `json:"formErrors"`
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
				"base":                  path.Base,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"getFileType": func(name string) FileType {
					return AllowedFileTypes[path.Ext(name)]
				},
			}
			tmpl, err := template.New("export.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/export.html")
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
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		names := r.Form["name"]

		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case ".":
			response.ExportParent = true
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidParent"
					writeResponse(w, r, response)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
			if len(names) == 0 {
				response.ExportParent = true
			} else {
				seen := make(map[string]bool)
				n := 0
				for _, name := range names {
					name := filepath.ToSlash(name)
					if strings.Contains(name, "/") {
						continue
					}
					if seen[name] {
						continue
					}
					seen[name] = true
					names[n] = name
					n++
				}
				names = names[:n]
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		if nbrew.DB != nil {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM export_job WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				},
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if exists {
				response.Error = "ExportLimitReached"
				writeResponse(w, r, response)
				return
			}
		}

		var totalBytes atomic.Int64
		outputDirsToExport := make(map[string]exportAction)
		group, groupctx := errgroup.WithContext(r.Context())
		if response.ExportParent {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				size, err := exportDirSize(r.Context(), nbrew.FS.WithContext(r.Context()), sitePrefix, response.Parent)
				if err != nil {
					return err
				}
				totalBytes.Add(size)
				return nil
			})
			if head == "pages" {
				if tail == "" {
					outputDir := "output"
					outputDirsToExport[outputDir] = exportFiles | exportDirectories
				} else {
					outputDir := path.Join("output", tail)
					outputDirsToExport[outputDir] = exportDirectories
				}
			} else if head == "posts" {
				outputDir := path.Join("output/posts", tail)
				outputDirsToExport[outputDir] = exportFiles | exportDirectories
			}
		} else {
			response.Files = make([]File, len(names))
			for i, name := range names {
				i, name := i, name
				if name == "" {
					continue
				}
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				file := File{
					Name:    fileInfo.Name(),
					IsDir:   fileInfo.IsDir(),
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				}
				if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
					file.FileID = databaseFileInfo.FileID
					file.CreationTime = databaseFileInfo.CreationTime
				} else {
					var absolutePath string
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						var directoryFS *DirectoryFS
						if v.As(&directoryFS) {
							absolutePath = path.Join(directoryFS.RootDir, sitePrefix, response.Parent, name)
						}
					}
					file.CreationTime = CreationTime(absolutePath, fileInfo)
				}
				response.Files[i] = file
				if !fileInfo.IsDir() {
					totalBytes.Add(fileInfo.Size())
				} else {
					group.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						size, err := exportDirSize(r.Context(), nbrew.FS.WithContext(r.Context()), sitePrefix, path.Join(response.Parent, name))
						if err != nil {
							return err
						}
						totalBytes.Add(size)
						return nil
					})
				}
				if head == "pages" {
					if file.IsDir {
						outputDir := path.Join("output", tail, name)
						outputDirsToExport[outputDir] |= exportDirectories
					} else {
						if tail == "" {
							if name == "index.html" {
								outputDir := "output"
								outputDirsToExport[outputDir] |= exportFiles
							} else {
								outputDir := path.Join("output", strings.TrimSuffix(name, ".html"))
								outputDirsToExport[outputDir] |= exportFiles
							}
						} else {
							outputDir := path.Join("output", tail, strings.TrimSuffix(name, ".html"))
							outputDirsToExport[outputDir] |= exportFiles
						}
					}
				} else if head == "posts" {
					if file.IsDir {
						if tail == "" {
							category := name
							outputDir := path.Join("output/posts", category)
							outputDirsToExport[outputDir] |= exportDirectories
						}
					} else {
						if !strings.Contains(tail, "/") {
							if strings.HasSuffix(name, ".md") {
								outputDir := path.Join("output/posts", tail, strings.TrimSuffix(name, ".md"))
								outputDirsToExport[outputDir] |= exportFiles
							}
						}
					}
				}
			}
		}
		for outputDir, action := range outputDirsToExport {
			outputDir, action := outputDir, action
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, outputDir))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					delete(outputDirsToExport, outputDir)
					continue
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			} else {
				if !fileInfo.IsDir() {
					delete(outputDirsToExport, outputDir)
					continue
				}
			}
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				size, err := exportOutputDirSize(r.Context(), nbrew.FS.WithContext(r.Context()), sitePrefix, outputDir, action)
				if err != nil {
					return err
				}
				totalBytes.Add(size)
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.TotalBytes = totalBytes.Load()
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
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
				values := url.Values{
					"parent": []string{response.Parent},
					"name":   response.Names,
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "export")+"/?"+values.Encode(), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":        "export",
					"tgzFileName": response.OutputName + ".tgz",
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
			request.Parent = r.Form.Get("parent")
			request.Names = r.Form["name"]
			request.OutputName = r.Form.Get("outputName")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Names:      make([]string, 0, len(request.Names)),
			OutputName: filenameSafe(request.OutputName),
			FormErrors: url.Values{},
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case ".":
			response.ExportParent = true
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidParent"
					writeResponse(w, r, response)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
			if len(request.Names) == 0 {
				response.ExportParent = true
			} else {
				seen := make(map[string]bool)
				for _, name := range request.Names {
					name := filepath.ToSlash(name)
					if strings.Contains(name, "/") {
						continue
					}
					if seen[name] {
						continue
					}
					seen[name] = true
					response.Names = append(response.Names, name)
				}
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		startTime := time.Now().UTC()
		if response.OutputName == "" {
			response.OutputName = "files-" + strings.ReplaceAll(startTime.Format("2006-01-02-150405.999"), ".", "-")
		}
		tgzFileName := response.OutputName + ".tgz"
		_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "exports", tgzFileName))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			response.FormErrors.Add("outputName", "file name already exists")
			writeResponse(w, r, response)
			return
		}

		var totalBytes atomic.Int64
		var filePaths []string
		outputDirsToExport := make(map[string]exportAction)
		group, groupctx := errgroup.WithContext(r.Context())
		if response.ExportParent {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				size, err := exportDirSize(r.Context(), nbrew.FS.WithContext(r.Context()), sitePrefix, response.Parent)
				if err != nil {
					return err
				}
				totalBytes.Add(size)
				return nil
			})
			filePaths = []string{response.Parent}
			if head == "pages" {
				if tail == "" {
					outputDir := "output"
					outputDirsToExport[outputDir] = exportFiles | exportDirectories
				} else {
					outputDir := path.Join("output", tail)
					outputDirsToExport[outputDir] = exportDirectories
				}
			} else if head == "posts" {
				outputDir := path.Join("output/posts", tail)
				outputDirsToExport[outputDir] = exportFiles | exportDirectories
			}
		} else {
			for _, name := range response.Names {
				name := name
				if name == "" {
					continue
				}
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				filePaths = append(filePaths, path.Join(response.Parent, name))
				isDir := fileInfo.IsDir()
				if !isDir {
					totalBytes.Add(fileInfo.Size())
				} else {
					group.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						size, err := exportDirSize(r.Context(), nbrew.FS.WithContext(r.Context()), sitePrefix, path.Join(response.Parent, name))
						if err != nil {
							return err
						}
						totalBytes.Add(size)
						return nil
					})
				}
				if head == "pages" {
					if isDir {
						outputDir := path.Join("output", tail, name)
						outputDirsToExport[outputDir] |= exportDirectories
					} else {
						if tail == "" {
							if name == "index.html" {
								outputDir := "output"
								outputDirsToExport[outputDir] |= exportFiles
							} else {
								outputDir := path.Join("output", strings.TrimSuffix(name, ".html"))
								outputDirsToExport[outputDir] |= exportFiles
							}
						} else {
							outputDir := path.Join("output", tail, strings.TrimSuffix(name, ".html"))
							outputDirsToExport[outputDir] |= exportFiles
						}
					}
				} else if head == "posts" {
					if isDir {
						if tail == "" {
							category := name
							outputDir := path.Join("output/posts", category)
							outputDirsToExport[outputDir] |= exportDirectories
						}
					} else {
						if !strings.Contains(tail, "/") {
							if strings.HasSuffix(name, ".md") {
								outputDir := path.Join("output/posts", tail, strings.TrimSuffix(name, ".md"))
								outputDirsToExport[outputDir] |= exportFiles
							}
						}
					}
				}
			}
		}
		for outputDir, action := range outputDirsToExport {
			outputDir, action := outputDir, action
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, outputDir))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					delete(outputDirsToExport, outputDir)
					continue
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			} else {
				if !fileInfo.IsDir() {
					delete(outputDirsToExport, outputDir)
					continue
				}
			}
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				size, err := exportOutputDirSize(r.Context(), nbrew.FS.WithContext(r.Context()), sitePrefix, outputDir, action)
				if err != nil {
					return err
				}
				totalBytes.Add(size)
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.TotalBytes = totalBytes.Load()

		var storageRemaining *atomic.Int64
		var isDatabaseFS bool
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			isDatabaseFS = v.As(&DatabaseFS{})
		}
		if nbrew.DB != nil && isDatabaseFS && user.StorageLimit >= 0 {
			storageUsed, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM site" +
					" JOIN site_owner ON site_owner.site_id = site.site_id" +
					" WHERE site_owner.user_id = {userID}",
				Values: []any{
					sq.UUIDParam("userID", user.UserID),
				},
			}, func(row *sq.Row) int64 {
				return row.Int64("sum(CASE WHEN site.storage_used IS NOT NULL AND site.storage_used > 0 THEN site.storage_used ELSE 0 END)")
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			storageRemaining = &atomic.Int64{}
			storageRemaining.Store(user.StorageLimit - storageUsed)
		}

		// 1. prepare the row to be inserted
		// 2. attempt to acquire a slot (insert the row)
		// 3. if insertion fails with KeyViolation, then report to user that a job is already running
		if nbrew.DB == nil {
			err := nbrew.exportTgz(r.Context(), ID{}, sitePrefix, filePaths, outputDirsToExport, tgzFileName, storageRemaining)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			exportJobID := NewID()
			_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO export_job (export_job_id, site_id, tgz_file_name, start_time, total_bytes)" +
					" VALUES ({exportJobID}, (SELECT site_id FROM site WHERE site_name = {siteName}), {tgzFileName}, {startTime}, {totalBytes})",
				Values: []any{
					sq.UUIDParam("exportJobID", exportJobID),
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.StringParam("tgzFileName", tgzFileName),
					sq.TimeParam("startTime", startTime),
					sq.Int64Param("totalBytes", response.TotalBytes),
				},
			})
			if err != nil {
				if nbrew.ErrorCode != nil {
					errorCode := nbrew.ErrorCode(err)
					if IsKeyViolation(nbrew.Dialect, errorCode) {
						response.Error = "ExportLimitReached"
						writeResponse(w, r, response)
						return
					}
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			nbrew.BaseCtxWaitGroup.Add(1)
			logger := nbrew.GetLogger(r.Context())
			requestURL := r.Method + " " + r.Host + r.URL.RequestURI()
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println(stacktrace.New(fmt.Errorf("panic: %s: %v", requestURL, v)))
					}
				}()
				defer nbrew.BaseCtxWaitGroup.Done()
				err := nbrew.exportTgz(nbrew.BaseCtx, exportJobID, sitePrefix, filePaths, outputDirsToExport, tgzFileName, storageRemaining)
				if err != nil {
					logger.Error(err.Error(),
						slog.String("exportJobID", exportJobID.String()),
						slog.String("sitePrefix", sitePrefix),
						slog.String("filePaths", strings.Join(filePaths, "|")),
						slog.String("tgzFileName", tgzFileName),
					)
				}
			}()
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}

func (nbrew *Notebrew) exportTgz(ctx context.Context, exportJobID ID, sitePrefix string, filePaths []string, outputDirsToExport map[string]exportAction, tgzFileName string, storageRemaining *atomic.Int64) error {
	success := false
	defer func() {
		if nbrew.DB == nil {
			return
		}
		_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM export_job WHERE export_job_id = {exportJobID}",
			Values: []any{
				sq.UUIDParam("exportJobID", exportJobID),
			},
		})
		if err != nil {
			nbrew.Logger.Error(err.Error())
		}
		if !success {
			err := nbrew.FS.WithContext(context.Background()).Remove(path.Join(sitePrefix, "exports", tgzFileName))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					nbrew.Logger.Error(err.Error())
				}
			}
		}
	}()
	writerCtx, cancelWriter := context.WithCancel(ctx)
	defer cancelWriter()
	writer, err := nbrew.FS.WithContext(writerCtx).OpenWriter(path.Join(sitePrefix, "exports", tgzFileName), 0644)
	if err != nil {
		return stacktrace.New(err)
	}
	defer func() {
		cancelWriter()
		writer.Close()
	}()
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(writer)
	defer func() {
		gzipWriter.Close()
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	var dest io.Writer
	if nbrew.DB == nil {
		dest = gzipWriter
	} else {
		var db sq.DB
		if nbrew.Dialect == "sqlite" {
			db = nbrew.DB
		} else {
			var conn *sql.Conn
			conn, err = nbrew.DB.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			db = conn
		}
		preparedExec, err := sq.PrepareExec(ctx, db, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE export_job SET processed_bytes = {processedBytes} WHERE export_job_id = {exportJobID}",
			Values: []any{
				sq.Int64Param("processedBytes", 0),
				sq.UUIDParam("exportJobID", exportJobID),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
		defer preparedExec.Close()
		dest = &exportProgressWriter{
			ctx:              writerCtx,
			writer:           gzipWriter,
			preparedExec:     preparedExec,
			processedBytes:   0,
			storageRemaining: storageRemaining,
		}
	}
	tarWriter := tar.NewWriter(dest)
	defer tarWriter.Close()
	outputDirs := make([]string, 0, len(outputDirsToExport))
	for outputDir := range outputDirsToExport {
		outputDirs = append(outputDirs, outputDir)
	}
	slices.Sort(outputDirs)
	databaseFS, ok := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		type File struct {
			FileID       ID
			FilePath     string
			IsDir        bool
			Size         int64
			ModTime      time.Time
			CreationTime time.Time
			Bytes        []byte
			IsPinned     bool
		}
		buf := bufPool.Get().(*bytes.Buffer).Bytes()
		defer func() {
			if cap(buf) <= maxPoolableBufferCapacity {
				buf = buf[:0]
				bufPool.Put(bytes.NewBuffer(buf))
			}
		}()
		gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
		defer func() {
			if gzipReader != nil {
				gzipReader.Reset(bytes.NewReader(nil))
				gzipReaderPool.Put(gzipReader)
			}
		}()
		for _, filePath := range filePaths {
			if filePath == "." {
				err := exportDir(ctx, tarWriter, nbrew.FS.WithContext(ctx), sitePrefix, ".")
				if err != nil {
					return stacktrace.New(err)
				}
				continue
			}
			file, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" LEFT JOIN pinned_file ON pinned_file.parent_id = files.parent_id AND pinned_file.file_id = files.file_id" +
					" WHERE file_path = {filePath}",
				Values: []any{
					sq.Param("filePath", path.Join(sitePrefix, filePath)),
				},
			}, func(row *sq.Row) (file File) {
				buf = row.Bytes(buf[:0], "COALESCE(files.text, files.data)")
				file.FileID = row.UUID("files.file_id")
				file.FilePath = strings.TrimPrefix(strings.TrimPrefix(row.String("files.file_path"), sitePrefix), "/")
				file.IsDir = row.Bool("files.is_dir")
				file.Size = row.Int64("files.size")
				file.Bytes = buf
				file.ModTime = row.Time("files.mod_time")
				file.CreationTime = row.Time("files.creation_time")
				file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
				return file
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				return stacktrace.New(err)
			}
			tarHeader := &tar.Header{
				Name:    file.FilePath,
				ModTime: file.ModTime,
				Size:    file.Size,
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			}
			if file.IsPinned {
				tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
			}
			if file.IsDir {
				tarHeader.Typeflag = tar.TypeDir
				tarHeader.Mode = 0755
				err = tarWriter.WriteHeader(tarHeader)
				if err != nil {
					return stacktrace.New(err)
				}
				err = exportDir(ctx, tarWriter, databaseFS.WithContext(ctx), sitePrefix, filePath)
				if err != nil {
					return stacktrace.New(err)
				}
				continue
			}
			fileType, ok := AllowedFileTypes[path.Ext(file.FilePath)]
			if !ok {
				continue
			}
			if (fileType.Has(AttributeImg) || fileType.Has(AttributeVideo)) && len(file.Bytes) > 0 && utf8.Valid(file.Bytes) {
				tarHeader.PAXRecords["NOTEBREW.file.caption"] = string(file.Bytes)
			}
			tarHeader.Typeflag = tar.TypeReg
			tarHeader.Mode = 0644
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return stacktrace.New(err)
			}
			if fileType.Has(AttributeObject) {
				reader, err := databaseFS.ObjectStorage.Get(ctx, file.FileID.String()+path.Ext(file.FilePath))
				if err != nil {
					return stacktrace.New(err)
				}
				_, err = io.Copy(tarWriter, reader)
				if err != nil {
					reader.Close()
					return stacktrace.New(err)
				}
				err = reader.Close()
				if err != nil {
					return stacktrace.New(err)
				}
			} else {
				if fileType.Has(AttributeGzippable) && !IsFulltextIndexed(file.FilePath) {
					if gzipReader == nil {
						gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
						if err != nil {
							return stacktrace.New(err)
						}
					} else {
						err = gzipReader.Reset(bytes.NewReader(file.Bytes))
						if err != nil {
							return stacktrace.New(err)
						}
					}
					_, err = io.Copy(tarWriter, gzipReader)
					if err != nil {
						return stacktrace.New(err)
					}
				} else {
					_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
					if err != nil {
						return stacktrace.New(err)
					}
				}
			}
		}
		for _, outputDir := range outputDirs {
			file, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" LEFT JOIN pinned_file ON pinned_file.parent_id = files.parent_id AND pinned_file.file_id = files.file_id" +
					" WHERE file_path = {outputDir}" +
					" AND is_dir",
				Values: []any{
					sq.Param("outputDir", path.Join(sitePrefix, outputDir)),
				},
			}, func(row *sq.Row) (file File) {
				file.FileID = row.UUID("files.file_id")
				file.FilePath = strings.TrimPrefix(strings.TrimPrefix(row.String("files.file_path"), sitePrefix), "/")
				file.IsDir = row.Bool("files.is_dir")
				file.Size = row.Int64("files.size")
				file.ModTime = row.Time("files.mod_time")
				file.CreationTime = row.Time("files.creation_time")
				file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
				return file
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				return stacktrace.New(err)
			}
			tarHeader := &tar.Header{
				Typeflag: tar.TypeDir,
				Mode:     0755,
				Name:     file.FilePath,
				ModTime:  file.ModTime,
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			}
			if file.IsPinned {
				tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
			}
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return stacktrace.New(err)
			}
			action := outputDirsToExport[outputDir]
			err = exportOutputDir(ctx, tarWriter, databaseFS.WithContext(ctx), sitePrefix, outputDir, action)
			if err != nil {
				return stacktrace.New(err)
			}
		}
	} else {
		for _, filePath := range filePaths {
			if filePath == "." {
				err := exportDir(ctx, tarWriter, nbrew.FS.WithContext(ctx), sitePrefix, ".")
				if err != nil {
					return stacktrace.New(err)
				}
				continue
			}
			file, err := nbrew.FS.WithContext(ctx).Open(path.Join(sitePrefix, filePath))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			fileInfo, err := file.Stat()
			if err != nil {
				file.Close()
				return stacktrace.New(err)
			}
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, filePath)
				}
			}
			modTime := fileInfo.ModTime()
			creationTime := CreationTime(absolutePath, fileInfo)
			tarHeader := &tar.Header{
				Name:    filePath,
				ModTime: modTime,
				Size:    fileInfo.Size(),
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			}
			if fileInfo.IsDir() {
				file.Close()
				tarHeader.Typeflag = tar.TypeDir
				tarHeader.Mode = 0755
				err := tarWriter.WriteHeader(tarHeader)
				if err != nil {
					return stacktrace.New(err)
				}
				continue
			}
			_, ok := AllowedFileTypes[path.Ext(filePath)]
			if !ok {
				file.Close()
				continue
			}
			tarHeader.Typeflag = tar.TypeReg
			tarHeader.Mode = 0644
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				file.Close()
				return stacktrace.New(err)
			}
			_, err = io.Copy(tarWriter, file)
			if err != nil {
				file.Close()
				return stacktrace.New(err)
			}
			file.Close()
		}
		for _, outputDir := range outputDirs {
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), path.Join(sitePrefix, outputDir))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return stacktrace.New(err)
			}
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, sitePrefix, outputDir)
				}
			}
			modTime := fileInfo.ModTime()
			creationTime := CreationTime(absolutePath, fileInfo)
			err = tarWriter.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Mode:     0755,
				Name:     outputDir,
				ModTime:  modTime,
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			})
			if err != nil {
				return stacktrace.New(err)
			}
			action := outputDirsToExport[outputDir]
			err = exportOutputDir(ctx, tarWriter, nbrew.FS.WithContext(ctx), sitePrefix, outputDir, action)
			if err != nil {
				return stacktrace.New(err)
			}
		}
	}
	err = tarWriter.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	err = gzipWriter.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	err = writer.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	success = true
	return nil
}

func exportDirSize(ctx context.Context, fsys fs.FS, sitePrefix string, dir string) (int64, error) {
	databaseFS, ok := &DatabaseFS{}, false
	switch v := fsys.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		var condition sq.Expression
		if dir == "." {
			condition = sq.Expr("("+
				"files.file_path = {notes}"+
				" OR files.file_path = {pages}"+
				" OR files.file_path = {posts}"+
				" OR files.file_path = {output}"+
				" OR files.file_path LIKE {notesPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {pagesPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {postsPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {outputPrefix} ESCAPE '\\'"+
				" OR files.file_path = {siteJSON}"+
				")",
				sq.StringParam("notes", path.Join(sitePrefix, "notes")),
				sq.StringParam("pages", path.Join(sitePrefix, "pages")),
				sq.StringParam("posts", path.Join(sitePrefix, "posts")),
				sq.StringParam("output", path.Join(sitePrefix, "output")),
				sq.StringParam("notesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "notes"))+"/%"),
				sq.StringParam("pagesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "pages"))+"/%"),
				sq.StringParam("postsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "posts"))+"/%"),
				sq.StringParam("outputPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output"))+"/%"),
				sq.StringParam("siteJSON", path.Join(sitePrefix, "site.json")),
			)
		} else {
			condition = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(path.Join(sitePrefix, dir))+"/%")
		}
		size, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE {condition}",
			Values: []any{
				sq.Param("condition", condition),
			},
		}, func(row *sq.Row) int64 {
			return row.Int64("sum(CASE WHEN files.is_dir OR files.size IS NULL THEN 0 ELSE files.size END)")
		})
		if err != nil {
			return 0, stacktrace.New(err)
		}
		return size, nil
	}
	var size int64
	walkDirFunc := func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return stacktrace.New(err)
		}
		if dirEntry.IsDir() {
			return nil
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return stacktrace.New(err)
		}
		size += fileInfo.Size()
		return nil
	}
	if dir == "." {
		for _, root := range []string{
			path.Join(sitePrefix, "notes"),
			path.Join(sitePrefix, "pages"),
			path.Join(sitePrefix, "posts"),
			path.Join(sitePrefix, "output"),
			path.Join(sitePrefix, "site.json"),
		} {
			err := fs.WalkDir(fsys, root, walkDirFunc)
			if err != nil {
				return 0, err
			}
		}
	} else {
		root := path.Join(sitePrefix, dir)
		err := fs.WalkDir(fsys, root, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if filePath == root {
				return nil
			}
			return walkDirFunc(filePath, dirEntry, err)
		})
		if err != nil {
			return 0, err
		}
	}
	return size, nil
}

func exportDir(ctx context.Context, tarWriter *tar.Writer, fsys fs.FS, sitePrefix string, dir string) error {
	databaseFS, ok := &DatabaseFS{}, false
	switch v := fsys.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		type File struct {
			FileID       ID
			FilePath     string
			IsDir        bool
			Size         int64
			ModTime      time.Time
			CreationTime time.Time
			Bytes        []byte
			IsPinned     bool
		}
		buf := bufPool.Get().(*bytes.Buffer).Bytes()
		defer func() {
			if cap(buf) <= maxPoolableBufferCapacity {
				buf = buf[:0]
				bufPool.Put(bytes.NewBuffer(buf))
			}
		}()
		gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
		defer func() {
			if gzipReader != nil {
				gzipReader.Reset(bytes.NewReader(nil))
				gzipReaderPool.Put(gzipReader)
			}
		}()
		var condition sq.Expression
		if dir == "." {
			condition = sq.Expr("("+
				"files.file_path = {notes}"+
				" OR files.file_path = {pages}"+
				" OR files.file_path = {posts}"+
				" OR files.file_path = {output}"+
				" OR files.file_path LIKE {notesPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {pagesPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {postsPrefix} ESCAPE '\\'"+
				" OR files.file_path LIKE {outputPrefix} ESCAPE '\\'"+
				" OR files.file_path = {siteJSON}"+
				")",
				sq.StringParam("notes", path.Join(sitePrefix, "notes")),
				sq.StringParam("pages", path.Join(sitePrefix, "pages")),
				sq.StringParam("posts", path.Join(sitePrefix, "posts")),
				sq.StringParam("output", path.Join(sitePrefix, "output")),
				sq.StringParam("notesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "notes"))+"/%"),
				sq.StringParam("pagesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "pages"))+"/%"),
				sq.StringParam("postsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "posts"))+"/%"),
				sq.StringParam("outputPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output"))+"/%"),
				sq.StringParam("siteJSON", path.Join(sitePrefix, "site.json")),
			)
		} else {
			condition = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(path.Join(sitePrefix, dir))+"/%")
		}
		cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" LEFT JOIN pinned_file ON pinned_file.parent_id = files.parent_id AND pinned_file.file_id = files.file_id" +
				" WHERE {condition}" +
				" ORDER BY file_path",
			Values: []any{
				sq.Param("condition", condition),
			},
		}, func(row *sq.Row) (file File) {
			buf = row.Bytes(buf[:0], "COALESCE(files.text, files.data)")
			file.FileID = row.UUID("files.file_id")
			file.FilePath = strings.TrimPrefix(strings.TrimPrefix(row.String("files.file_path"), sitePrefix), "/")
			file.IsDir = row.Bool("files.is_dir")
			file.Size = row.Int64("files.size")
			file.Bytes = buf
			file.ModTime = row.Time("files.mod_time")
			file.CreationTime = row.Time("files.creation_time")
			file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
			return file
		})
		if err != nil {
			return stacktrace.New(err)
		}
		defer cursor.Close()
		for cursor.Next() {
			file, err := cursor.Result()
			if err != nil {
				return stacktrace.New(err)
			}
			tarHeader := &tar.Header{
				Name:    file.FilePath,
				ModTime: file.ModTime,
				Size:    file.Size,
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			}
			if file.IsPinned {
				tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
			}
			if file.IsDir {
				tarHeader.Typeflag = tar.TypeDir
				tarHeader.Mode = 0755
				err = tarWriter.WriteHeader(tarHeader)
				if err != nil {
					return stacktrace.New(err)
				}
				continue
			}
			fileType, ok := AllowedFileTypes[path.Ext(file.FilePath)]
			if !ok {
				continue
			}
			if (fileType.Has(AttributeImg) || fileType.Has(AttributeVideo)) && len(file.Bytes) > 0 && utf8.Valid(file.Bytes) {
				tarHeader.PAXRecords["NOTEBREW.file.caption"] = string(file.Bytes)
			}
			tarHeader.Typeflag = tar.TypeReg
			tarHeader.Mode = 0644
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return stacktrace.New(err)
			}
			if fileType.Has(AttributeObject) {
				reader, err := databaseFS.ObjectStorage.Get(ctx, file.FileID.String()+path.Ext(file.FilePath))
				if err != nil {
					return err
				}
				_, err = io.Copy(tarWriter, reader)
				if err != nil {
					reader.Close()
					return stacktrace.New(err)
				}
				err = reader.Close()
				if err != nil {
					return stacktrace.New(err)
				}
			} else {
				if fileType.Has(AttributeGzippable) && !IsFulltextIndexed(file.FilePath) {
					if gzipReader == nil {
						gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
						if err != nil {
							return stacktrace.New(err)
						}
					} else {
						err = gzipReader.Reset(bytes.NewReader(file.Bytes))
						if err != nil {
							return stacktrace.New(err)
						}
					}
					_, err = io.Copy(tarWriter, gzipReader)
					if err != nil {
						return stacktrace.New(err)
					}
				} else {
					_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
					if err != nil {
						return stacktrace.New(err)
					}
				}
			}
		}
		err = cursor.Close()
		if err != nil {
			return stacktrace.New(err)
		}
		return nil
	}
	walkDirFunc := func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return stacktrace.New(err)
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return stacktrace.New(err)
		}
		var absolutePath string
		switch v := fsys.(type) {
		case interface{ As(any) bool }:
			var directoryFS *DirectoryFS
			if v.As(&directoryFS) {
				absolutePath = path.Join(directoryFS.RootDir, filePath)
			}
		}
		modTime := fileInfo.ModTime()
		creationTime := CreationTime(absolutePath, fileInfo)
		tarHeader := &tar.Header{
			Name:    filePath,
			ModTime: modTime,
			Size:    fileInfo.Size(),
			PAXRecords: map[string]string{
				"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
				"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
			},
		}
		if dirEntry.IsDir() {
			tarHeader.Typeflag = tar.TypeDir
			tarHeader.Mode = 0755
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		}
		_, ok := AllowedFileTypes[path.Ext(filePath)]
		if !ok {
			return nil
		}
		tarHeader.Typeflag = tar.TypeReg
		tarHeader.Mode = 0644
		err = tarWriter.WriteHeader(tarHeader)
		if err != nil {
			return stacktrace.New(err)
		}
		file, err := fsys.Open(filePath)
		if err != nil {
			return stacktrace.New(err)
		}
		defer file.Close()
		_, err = io.Copy(tarWriter, file)
		if err != nil {
			return stacktrace.New(err)
		}
		return nil
	}
	if dir == "." {
		for _, root := range []string{
			path.Join(sitePrefix, "notes"),
			path.Join(sitePrefix, "pages"),
			path.Join(sitePrefix, "posts"),
			path.Join(sitePrefix, "output"),
			path.Join(sitePrefix, "site.json"),
		} {
			err := fs.WalkDir(fsys, root, walkDirFunc)
			if err != nil {
				return stacktrace.New(err)
			}
		}
	} else {
		root := path.Join(sitePrefix, dir)
		err := fs.WalkDir(fsys, root, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if filePath == root {
				return nil
			}
			return walkDirFunc(filePath, dirEntry, err)
		})
		if err != nil {
			return stacktrace.New(err)
		}
	}
	return nil
}

func exportOutputDirSize(ctx context.Context, fsys fs.FS, sitePrefix string, outputDir string, action exportAction) (int64, error) {
	head, tail, _ := strings.Cut(outputDir, "/")
	if head != "output" {
		return 0, fmt.Errorf("programmer error: attempted to export output directory %s (which is not an output directory)", outputDir)
	}
	if action == 0 {
		return 0, nil
	}
	nextHead, nextTail, _ := strings.Cut(tail, "/")
	if action&exportFiles != 0 && action&exportDirectories == 0 {
		if nextTail != "" {
			var counterpart string
			if nextHead == "posts" {
				counterpart = path.Join(sitePrefix, "posts", nextTail)
			} else {
				counterpart = path.Join(sitePrefix, "pages", nextTail)
			}
			counterpartFileInfo, err := fs.Stat(fsys, counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return 0, stacktrace.New(err)
				}
			} else if counterpartFileInfo.IsDir() {
				dirEntries, err := fs.ReadDir(fsys, path.Join(sitePrefix, outputDir))
				if err != nil {
					return 0, stacktrace.New(err)
				}
				var totalSize int64
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					fileInfo, err := dirEntry.Info()
					if err != nil {
						return 0, stacktrace.New(err)
					}
					totalSize += fileInfo.Size()
				}
				return totalSize, nil
			}
		}
	}
	if action&exportFiles == 0 && action&exportDirectories != 0 {
		if tail != "" {
			var counterpart string
			if head == "posts" {
				counterpart = path.Join(sitePrefix, "posts", tail+".md")
			} else {
				counterpart = path.Join(sitePrefix, "pages", tail+".html")
			}
			counterpartFileInfo, err := fs.Stat(fsys, counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return 0, stacktrace.New(err)
				}
			} else if !counterpartFileInfo.IsDir() {
				dirEntries, err := fs.ReadDir(fsys, path.Join(sitePrefix, outputDir))
				if err != nil {
					return 0, stacktrace.New(err)
				}
				var totalSize atomic.Int64
				group, groupctx := errgroup.WithContext(ctx)
				for _, dirEntry := range dirEntries {
					if !dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					group.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						size, err := exportOutputDirSize(groupctx, fsys, sitePrefix, path.Join(outputDir, name), exportFiles|exportDirectories)
						if err != nil {
							return stacktrace.New(err)
						}
						totalSize.Add(size)
						return nil
					})
				}
				err = group.Wait()
				if err != nil {
					return 0, err
				}
				return totalSize.Load(), nil
			}
		}
	}
	databaseFS, ok := &DatabaseFS{}, false
	switch v := fsys.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		var condition sq.Expression
		if outputDir == "output" {
			condition = sq.Expr("files.file_path LIKE {outputPrefix} ESCAPE '\\'"+
				" AND files.file_path <> {outputPosts}"+
				" AND files.file_path <> {outputThemes}"+
				" AND files.file_path NOT LIKE {outputPostsPrefix} ESCAPE '\\'"+
				" AND files.file_path NOT LIKE {outputThemesPrefix} ESCAPE '\\'",
				sq.StringParam("outputPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output"))+"/%"),
				sq.StringParam("outputPosts", path.Join(sitePrefix, "output/posts")),
				sq.StringParam("outputThemes", path.Join(sitePrefix, "output/themes")),
				sq.StringParam("outputPostsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output/posts"))+"/%"),
				sq.StringParam("outputThemesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output/themes"))+"/%"),
			)
		} else {
			condition = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(path.Join(sitePrefix, outputDir))+"/%")
		}
		size, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE {condition}",
			Values: []any{
				sq.Param("condition", condition),
			},
		}, func(row *sq.Row) int64 {
			return row.Int64("sum(CASE WHEN files.is_dir OR files.size IS NULL THEN 0 ELSE files.size END)")
		})
		if err != nil {
			return 0, stacktrace.New(err)
		}
		return size, nil
	}
	var size int64
	root := path.Join(sitePrefix, outputDir)
	err := fs.WalkDir(fsys, root, func(filePath string, dirEntry fs.DirEntry, err error) error {
		if filePath == root {
			return nil
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return stacktrace.New(err)
		}
		if dirEntry.IsDir() {
			if outputDir == "output" {
				if filePath == path.Join(sitePrefix, "output/posts") || filePath == path.Join(sitePrefix, "output/themes") {
					return fs.SkipDir
				}
			}
			return nil
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return stacktrace.New(err)
		}
		size += fileInfo.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return size, nil
}

func exportOutputDir(ctx context.Context, tarWriter *tar.Writer, fsys fs.FS, sitePrefix string, outputDir string, action exportAction) error {
	type File struct {
		FileID       ID
		FilePath     string
		IsDir        bool
		Size         int64
		ModTime      time.Time
		CreationTime time.Time
		Bytes        []byte
		IsPinned     bool
	}
	head, tail, _ := strings.Cut(outputDir, "/")
	if head != "output" {
		return fmt.Errorf("programmer error: attempted to export output directory %s (which is not an output directory)", outputDir)
	}
	if action == 0 {
		return nil
	}
	nextHead, nextTail, _ := strings.Cut(tail, "/")
	if action&exportFiles != 0 && action&exportDirectories == 0 {
		if nextTail != "" {
			var counterpart string
			if nextHead == "posts" {
				counterpart = path.Join(sitePrefix, "posts", nextTail)
			} else {
				counterpart = path.Join(sitePrefix, "pages", nextTail)
			}
			counterpartFileInfo, err := fs.Stat(fsys, counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return stacktrace.New(err)
				}
			} else if counterpartFileInfo.IsDir() {
				// Export only the files.
				databaseFS, ok := &DatabaseFS{}, false
				switch v := fsys.(type) {
				case interface{ As(any) bool }:
					ok = v.As(&databaseFS)
				}
				if ok {
					buf := bufPool.Get().(*bytes.Buffer).Bytes()
					defer func() {
						if cap(buf) <= maxPoolableBufferCapacity {
							buf = buf[:0]
							bufPool.Put(bytes.NewBuffer(buf))
						}
					}()
					gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
					defer func() {
						if gzipReader != nil {
							gzipReader.Reset(bytes.NewReader(nil))
							gzipReaderPool.Put(gzipReader)
						}
					}()
					cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM files" +
							" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
							" AND NOT is_dir" +
							" ORDER BY file_path",
					}, func(row *sq.Row) (file File) {
						buf = row.Bytes(buf[:0], "COALESCE(files.text, files.data)")
						file.FileID = row.UUID("files.file_id")
						file.FilePath = strings.TrimPrefix(strings.TrimPrefix(row.String("files.file_path"), sitePrefix), "/")
						file.IsDir = row.Bool("files.is_dir")
						file.Size = row.Int64("files.size")
						file.Bytes = buf
						file.ModTime = row.Time("files.mod_time")
						file.CreationTime = row.Time("files.creation_time")
						file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
						return file
					})
					if err != nil {
						return stacktrace.New(err)
					}
					defer cursor.Close()
					for cursor.Next() {
						file, err := cursor.Result()
						if err != nil {
							return stacktrace.New(err)
						}
						fileType, ok := AllowedFileTypes[path.Ext(file.FilePath)]
						if !ok {
							continue
						}
						tarHeader := &tar.Header{
							Typeflag: tar.TypeReg,
							Mode:     0644,
							Name:     file.FilePath,
							ModTime:  file.ModTime,
							Size:     file.Size,
							PAXRecords: map[string]string{
								"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
								"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
							},
						}
						if file.IsPinned {
							tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
						}
						err = tarWriter.WriteHeader(tarHeader)
						if err != nil {
							return stacktrace.New(err)
						}
						if fileType.Has(AttributeObject) {
							reader, err := databaseFS.ObjectStorage.Get(ctx, file.FileID.String()+path.Ext(file.FilePath))
							if err != nil {
								return stacktrace.New(err)
							}
							_, err = io.Copy(tarWriter, reader)
							if err != nil {
								reader.Close()
								return stacktrace.New(err)
							}
							err = reader.Close()
							if err != nil {
								return stacktrace.New(err)
							}
						} else {
							if fileType.Has(AttributeGzippable) && !IsFulltextIndexed(file.FilePath) {
								if gzipReader == nil {
									gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
									if err != nil {
										return stacktrace.New(err)
									}
								} else {
									err = gzipReader.Reset(bytes.NewReader(file.Bytes))
									if err != nil {
										return stacktrace.New(err)
									}
								}
								_, err = io.Copy(tarWriter, gzipReader)
								if err != nil {
									return stacktrace.New(err)
								}
							} else {
								_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
								if err != nil {
									return stacktrace.New(err)
								}
							}
						}
					}
				} else {
					dirEntries, err := fs.ReadDir(fsys, path.Join(sitePrefix, outputDir))
					if err != nil {
						return stacktrace.New(err)
					}
					for _, dirEntry := range dirEntries {
						if dirEntry.IsDir() {
							continue
						}
						name := dirEntry.Name()
						_, ok := AllowedFileTypes[path.Ext(name)]
						if !ok {
							continue
						}
						file, err := fsys.Open(path.Join(sitePrefix, outputDir, name))
						if err != nil {
							return stacktrace.New(err)
						}
						fileInfo, err := file.Stat()
						if err != nil {
							file.Close()
							return stacktrace.New(err)
						}
						var absolutePath string
						switch v := fsys.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, outputDir, name)
							}
						}
						modTime := fileInfo.ModTime()
						creationTime := CreationTime(absolutePath, fileInfo)
						err = tarWriter.WriteHeader(&tar.Header{
							Typeflag: tar.TypeReg,
							Mode:     0644,
							Name:     path.Join(outputDir, name),
							ModTime:  modTime,
							Size:     fileInfo.Size(),
							PAXRecords: map[string]string{
								"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
								"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
							},
						})
						if err != nil {
							file.Close()
							return stacktrace.New(err)
						}
						_, err = io.Copy(tarWriter, file)
						if err != nil {
							file.Close()
							return stacktrace.New(err)
						}
						file.Close()
					}
				}
				return nil
			}
		}
	}
	if action&exportFiles == 0 && action&exportDirectories != 0 {
		if tail != "" {
			var counterpart string
			if head == "posts" {
				counterpart = path.Join(sitePrefix, "posts", tail+".md")
			} else {
				counterpart = path.Join(sitePrefix, "pages", tail+".html")
			}
			counterpartFileInfo, err := fs.Stat(fsys, counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return stacktrace.New(err)
				}
			} else if !counterpartFileInfo.IsDir() {
				// Export only the directories.
				var names []string
				databaseFS, ok := &DatabaseFS{}, false
				switch v := fsys.(type) {
				case interface{ As(any) bool }:
					ok = v.As(&databaseFS)
				}
				if ok {
					cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM files" +
							" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
							" AND is_dir" +
							" ORDER BY file_path",
					}, func(row *sq.Row) (file File) {
						file.FileID = row.UUID("files.file_id")
						file.FilePath = strings.TrimPrefix(strings.TrimPrefix(row.String("files.file_path"), sitePrefix), "/")
						file.IsDir = row.Bool("files.is_dir")
						file.Size = row.Int64("files.size")
						file.ModTime = row.Time("files.mod_time")
						file.CreationTime = row.Time("files.creation_time")
						file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
						return file
					})
					if err != nil {
						return stacktrace.New(err)
					}
					defer cursor.Close()
					var names []string
					for cursor.Next() {
						file, err := cursor.Result()
						if err != nil {
							return stacktrace.New(err)
						}
						tarHeader := &tar.Header{
							Typeflag: tar.TypeDir,
							Mode:     0755,
							Name:     file.FilePath,
							ModTime:  file.ModTime,
							PAXRecords: map[string]string{
								"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
								"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
							},
						}
						if file.IsPinned {
							tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
						}
						err = tarWriter.WriteHeader(tarHeader)
						if err != nil {
							return stacktrace.New(err)
						}
						names = append(names, path.Base(file.FilePath))
					}
				} else {
					dirEntries, err := fs.ReadDir(fsys, path.Join(sitePrefix, outputDir))
					if err != nil {
						return stacktrace.New(err)
					}
					for _, dirEntry := range dirEntries {
						if !dirEntry.IsDir() {
							continue
						}
						name := dirEntry.Name()
						fileInfo, err := dirEntry.Info()
						if err != nil {
							return stacktrace.New(err)
						}
						var absolutePath string
						switch v := fsys.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, outputDir, name)
							}
						}
						modTime := fileInfo.ModTime()
						creationTime := CreationTime(absolutePath, fileInfo)
						err = tarWriter.WriteHeader(&tar.Header{
							Typeflag: tar.TypeDir,
							Mode:     0755,
							Name:     path.Join(outputDir, name),
							ModTime:  modTime,
							PAXRecords: map[string]string{
								"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
								"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
							},
						})
						if err != nil {
							return stacktrace.New(err)
						}
						names = append(names, name)
					}
				}
				for _, name := range names {
					err = exportOutputDir(ctx, tarWriter, fsys, sitePrefix, path.Join(outputDir, name), exportFiles|exportDirectories)
					if err != nil {
						return stacktrace.New(err)
					}
				}
				return nil
			}
		}
	}
	databaseFS, ok := &DatabaseFS{}, false
	switch v := fsys.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		buf := bufPool.Get().(*bytes.Buffer).Bytes()
		defer func() {
			if cap(buf) <= maxPoolableBufferCapacity {
				buf = buf[:0]
				bufPool.Put(bytes.NewBuffer(buf))
			}
		}()
		gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
		defer func() {
			if gzipReader != nil {
				gzipReader.Reset(bytes.NewReader(nil))
				gzipReaderPool.Put(gzipReader)
			}
		}()
		var condition sq.Expression
		if outputDir == "output" {
			condition = sq.Expr("files.file_path LIKE {outputPrefix} ESCAPE '\\'"+
				" AND files.file_path <> {outputPosts}"+
				" AND files.file_path <> {outputThemes}"+
				" AND files.file_path NOT LIKE {outputPostsPrefix} ESCAPE '\\'"+
				" AND files.file_path NOT LIKE {outputThemesPrefix} ESCAPE '\\'",
				sq.StringParam("outputPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output"))+"/%"),
				sq.StringParam("outputPosts", path.Join(sitePrefix, "output/posts")),
				sq.StringParam("outputThemes", path.Join(sitePrefix, "output/themes")),
				sq.StringParam("outputPostsPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output/posts"))+"/%"),
				sq.StringParam("outputThemesPrefix", wildcardReplacer.Replace(path.Join(sitePrefix, "output/themes"))+"/%"),
			)
		} else {
			condition = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(path.Join(sitePrefix, outputDir))+"/%")
		}
		cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" LEFT JOIN pinned_file ON pinned_file.parent_id = files.parent_id AND pinned_file.file_id = files.file_id" +
				" WHERE {condition}" +
				" ORDER BY file_path",
			Values: []any{
				sq.Param("condition", condition),
			},
		}, func(row *sq.Row) (file File) {
			buf = row.Bytes(buf[:0], "COALESCE(files.text, files.data)")
			file.FileID = row.UUID("files.file_id")
			file.FilePath = strings.TrimPrefix(strings.TrimPrefix(row.String("files.file_path"), sitePrefix), "/")
			file.IsDir = row.Bool("files.is_dir")
			file.Size = row.Int64("files.size")
			file.Bytes = buf
			file.ModTime = row.Time("files.mod_time")
			file.CreationTime = row.Time("files.creation_time")
			file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
			return file
		})
		if err != nil {
			return stacktrace.New(err)
		}
		defer cursor.Close()
		for cursor.Next() {
			file, err := cursor.Result()
			if err != nil {
				return stacktrace.New(err)
			}
			tarHeader := &tar.Header{
				Name:    file.FilePath,
				ModTime: file.ModTime,
				Size:    file.Size,
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			}
			if file.IsPinned {
				tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
			}
			if file.IsDir {
				tarHeader.Typeflag = tar.TypeDir
				tarHeader.Mode = 0755
				err = tarWriter.WriteHeader(tarHeader)
				if err != nil {
					return stacktrace.New(err)
				}
				continue
			}
			fileType, ok := AllowedFileTypes[path.Ext(file.FilePath)]
			if !ok {
				continue
			}
			if (fileType.Has(AttributeImg) || fileType.Has(AttributeVideo)) && len(file.Bytes) > 0 && utf8.Valid(file.Bytes) {
				tarHeader.PAXRecords["NOTEBREW.file.caption"] = string(file.Bytes)
			}
			tarHeader.Typeflag = tar.TypeReg
			tarHeader.Mode = 0644
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return stacktrace.New(err)
			}
			if fileType.Has(AttributeObject) {
				reader, err := databaseFS.ObjectStorage.Get(ctx, file.FileID.String()+path.Ext(file.FilePath))
				if err != nil {
					return stacktrace.New(err)
				}
				_, err = io.Copy(tarWriter, reader)
				if err != nil {
					reader.Close()
					return stacktrace.New(err)
				}
				err = reader.Close()
				if err != nil {
					return stacktrace.New(err)
				}
			} else {
				if fileType.Has(AttributeGzippable) && !IsFulltextIndexed(file.FilePath) {
					if gzipReader == nil {
						gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
						if err != nil {
							return stacktrace.New(err)
						}
					} else {
						err = gzipReader.Reset(bytes.NewReader(file.Bytes))
						if err != nil {
							return stacktrace.New(err)
						}
					}
					_, err = io.Copy(tarWriter, gzipReader)
					if err != nil {
						return stacktrace.New(err)
					}
				} else {
					_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
					if err != nil {
						return stacktrace.New(err)
					}
				}
			}
		}
		err = cursor.Close()
		if err != nil {
			return stacktrace.New(err)
		}
		return nil
	}
	root := path.Join(sitePrefix, outputDir)
	err := fs.WalkDir(fsys, root, func(filePath string, dirEntry fs.DirEntry, err error) error {
		if filePath == root {
			return nil
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return stacktrace.New(err)
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return stacktrace.New(err)
		}
		var absolutePath string
		switch v := fsys.(type) {
		case interface{ As(any) bool }:
			var directoryFS *DirectoryFS
			if v.As(&directoryFS) {
				absolutePath = path.Join(directoryFS.RootDir, filePath)
			}
		}
		modTime := fileInfo.ModTime()
		creationTime := CreationTime(absolutePath, fileInfo)
		tarHeader := &tar.Header{
			Name:    filePath,
			ModTime: modTime,
			Size:    fileInfo.Size(),
			PAXRecords: map[string]string{
				"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
				"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
			},
		}
		if dirEntry.IsDir() {
			if outputDir == "output" {
				if filePath == path.Join(sitePrefix, "output/posts") || filePath == path.Join(sitePrefix, "output/themes") {
					return fs.SkipDir
				}
			}
			tarHeader.Typeflag = tar.TypeDir
			tarHeader.Mode = 0755
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		}
		_, ok := AllowedFileTypes[path.Ext(filePath)]
		if !ok {
			return nil
		}
		tarHeader.Typeflag = tar.TypeReg
		tarHeader.Mode = 0644
		err = tarWriter.WriteHeader(tarHeader)
		if err != nil {
			return stacktrace.New(err)
		}
		file, err := fsys.Open(filePath)
		if err != nil {
			return stacktrace.New(err)
		}
		defer file.Close()
		_, err = io.Copy(tarWriter, file)
		if err != nil {
			return stacktrace.New(err)
		}
		return nil
	})
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

type exportProgressWriter struct {
	ctx              context.Context
	writer           io.Writer
	preparedExec     *sq.PreparedExec
	processedBytes   int64
	storageRemaining *atomic.Int64
}

func (w *exportProgressWriter) Write(p []byte) (n int, err error) {
	err = w.ctx.Err()
	if err != nil {
		return 0, err
	}
	n, err = w.writer.Write(p)
	if err == nil {
		if w.storageRemaining != nil {
			if w.storageRemaining.Add(-int64(n)) < 1 {
				return n, ErrStorageLimitExceeded
			}
		}
	}
	if w.preparedExec == nil {
		return n, err
	}
	processedBytes := w.processedBytes + int64(n)
	if processedBytes%(1<<20) > w.processedBytes%(1<<20) {
		result, err := w.preparedExec.Exec(w.ctx, sq.Int64Param("processedBytes", processedBytes))
		if err != nil {
			return n, err
		}
		// We weren't able to update the database row, which means it has been
		// deleted (i.e. job canceled).
		if result.RowsAffected == 0 {
			return n, fmt.Errorf("export canceled")
		}
	}
	w.processedBytes = processedBytes
	return n, err
}
