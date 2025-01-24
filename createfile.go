package notebrew

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/parser"
	"golang.org/x/sync/errgroup"
)

var defaultMarkdown = goldmark.New(goldmark.WithParserOptions(parser.WithAttribute()))

func (nbrew *Notebrew) createfile(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent  string
		Name    string
		Ext     string
		Content string
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		Parent            string            `json:"parent"`
		FileExts          []string          `json:"fileExts"`
		UploadableExts    []string          `json:"uploadableExts"`
		Name              string            `json:"name"`
		Ext               string            `json:"ext"`
		Content           string            `json:"content"`
		Error             string            `json:"error"`
		FormErrors        url.Values        `json:"formErrors"`
		UploadCount       int64             `json:"uploadCount"`
		UploadSize        int64             `json:"uploadSize"`
		FilesTooBig       []string          `json:"filesTooBig"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
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
				"join":        path.Join,
				"base":        path.Base,
				"hasPrefix":   strings.HasPrefix,
				"trimPrefix":  strings.TrimPrefix,
				"joinStrings": strings.Join,
				"stylesCSS":   func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":  func() template.JS { return template.JS(BaselineJS) },
				"referer":     func() string { return referer },
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
				"tail": func(s string) string {
					_, tail, _ := strings.Cut(s, "/")
					return tail
				},
				"jsonArray": func(s []string) (string, error) {
					b, err := json.Marshal(s)
					if err != nil {
						return "", err
					}
					return string(b), nil
				},
			}
			tmpl, err := template.New("createfile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createfile.html")
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
		response.SitePrefix = sitePrefix
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			response.Ext = ".txt"
			response.FileExts = editableExts
		case "pages":
			response.Ext = ".html"
			response.FileExts = []string{".html"}
			response.UploadableExts = make([]string, 0, len(imgExts)+len(videoExts)+3)
			if !user.UserFlags["NoUploadImage"] {
				response.UploadableExts = append(response.UploadableExts, imgExts...)
			}
			if !user.UserFlags["NoUploadVideo"] {
				response.UploadableExts = append(response.UploadableExts, videoExts...)
			}
			response.UploadableExts = append(response.UploadableExts, ".css", ".js", ".md")
		case "posts":
			response.Ext = ".md"
			response.FileExts = []string{".md"}
			response.UploadableExts = make([]string, 0, len(imgExts)+len(videoExts))
			if !user.UserFlags["NoUploadImage"] {
				response.UploadableExts = append(response.UploadableExts, imgExts...)
			}
			if !user.UserFlags["NoUploadVideo"] {
				response.UploadableExts = append(response.UploadableExts, videoExts...)
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				response.Ext = ".html"
				response.FileExts = editableExts
			} else {
				response.Ext = ".md"
				response.FileExts = []string{".css", ".js", ".md"}
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		switch head {
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
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		slices.Sort(response.FileExts)
		slices.Sort(response.UploadableExts)
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
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "createfile")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "createfile",
				},
				"uploadCount":       response.UploadCount,
				"uploadSize":        response.UploadSize,
				"regenerationStats": response.RegenerationStats,
				"filesTooBig":       response.FilesTooBig,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, urlReplacer.Replace("/"+path.Join("files", sitePrefix, response.Parent, response.Name+response.Ext)), http.StatusFound)
		}

		var err error
		var request Request
		var reader *multipart.Reader
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := r.ParseForm()
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
			request.Parent = r.Form.Get("parent")
			request.Name = r.Form.Get("name")
			request.Ext = r.Form.Get("ext")
			request.Content = r.Form.Get("content")
		case "multipart/form-data":
			reader, err = r.MultipartReader()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			var maxBytesErr *http.MaxBytesError
			for i := 0; i < 4; i++ {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				var b strings.Builder
				_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
				if err != nil {
					if errors.As(err, &maxBytesErr) {
						nbrew.BadRequest(w, r, err)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				switch formName {
				case "parent":
					request.Parent = b.String()
				case "name":
					request.Name = b.String()
				case "ext":
					request.Ext = b.String()
				case "content":
					request.Content = b.String()
				}
			}
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Ext:        request.Ext,
			Content:    request.Content,
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
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
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		switch head {
		case "notes":
			if request.Name != "" {
				response.Name = filenameSafe(request.Name)
			} else {
				if response.Ext == ".md" || response.Ext == ".txt" {
					var line string
					remainder := response.Content
					for remainder != "" {
						line, remainder, _ = strings.Cut(remainder, "\n")
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						if response.Ext == ".md" {
							response.Name = filenameSafe(markdownTextOnly(defaultMarkdown.Parser(), []byte(line)))
						} else {
							response.Name = filenameSafe(line)
						}
						if response.Name == "" {
							continue
						}
						break
					}
				}
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			switch response.Ext {
			case "":
				response.Ext = ".txt"
			case ".html", ".css", ".js", ".md", ".txt":
				break
			default:
				response.FormErrors.Add("name", "invalid file extension")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "pages":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			ext := path.Ext(response.Name)
			if _, ok := AllowedFileTypes[ext]; ok {
				response.Name = strings.TrimSuffix(response.Name, ext)
			}
			switch response.Ext {
			case "":
				response.Ext = ".html"
			case ".html":
				break
			default:
				response.FormErrors.Add("name", "invalid file extension")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			if (tail == "" && response.Name == "posts" && response.Ext == ".html") ||
				(tail == "" && response.Name == "themes" && response.Ext == ".html") ||
				(tail != "" && response.Name == "index" && response.Ext == ".html") {
				response.FormErrors.Add("name", "this name is not allowed")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "posts":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			} else {
				remainder := response.Content
				for remainder != "" {
					response.Name, remainder, _ = strings.Cut(remainder, "\n")
					response.Name = strings.TrimSpace(response.Name)
					if response.Name == "" {
						continue
					}
					response.Name = urlSafe(markdownTextOnly(defaultMarkdown.Parser(), []byte(response.Name)))
					if response.Name == "" {
						continue
					}
					break
				}
			}
			ext := path.Ext(response.Name)
			if _, ok := AllowedFileTypes[ext]; ok {
				response.Name = strings.TrimSuffix(response.Name, ext)
			}
			switch response.Ext {
			case "":
				response.Ext = ".md"
			case ".md":
				break
			default:
				response.FormErrors.Add("name", "invalid file extension")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			var timestamp [8]byte
			binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
			prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			if response.Name != "" {
				response.Name = prefix + "-" + response.Name
			} else {
				response.Name = prefix
			}
		case "output":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				switch response.Ext {
				case "":
					response.Ext = ".html"
				case ".html", ".css", ".js", ".md", ".txt":
					break
				default:
					response.FormErrors.Add("name", "invalid file extension")
					response.Error = "FormErrorsPresent"
					writeResponse(w, r, response)
					return
				}
			} else {
				switch response.Ext {
				case "":
					response.Ext = ".js"
				case ".css", ".js", ".md":
					break
				default:
					response.FormErrors.Add("name", "invalid file extension")
					response.Error = "FormErrorsPresent"
					writeResponse(w, r, response)
					return
				}
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.Parent, response.Name+response.Ext))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			switch head {
			case "pages":
				response.FormErrors.Add("name", "page already exists")
			case "posts":
				response.FormErrors.Add("name", "post already exists")
			default:
				response.FormErrors.Add("name", "file already exists")
			}
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
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
		writerCtx, cancelWriter := context.WithCancel(r.Context())
		defer cancelWriter()
		writer, err := nbrew.FS.WithContext(writerCtx).OpenWriter(path.Join(sitePrefix, response.Parent, response.Name+response.Ext), 0644)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer func() {
			cancelWriter()
			writer.Close()
		}()
		var n int64
		if storageRemaining != nil {
			limitedWriter := &LimitedWriter{
				W:   writer,
				N:   storageRemaining.Load(),
				Err: ErrStorageLimitExceeded,
			}
			n, err = io.Copy(limitedWriter, strings.NewReader(response.Content))
			storageRemaining.Add(-n)
		} else {
			n, err = io.Copy(writer, strings.NewReader(response.Content))
		}
		if err != nil {
			if errors.Is(err, ErrStorageLimitExceeded) {
				nbrew.StorageLimitExceeded(w, r)
				return
			}
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

		if (head == "pages" || head == "posts") && contentType == "multipart/form-data" {
			var outputDir string
			if head == "posts" {
				outputDir = path.Join(sitePrefix, "output/posts", tail, response.Name)
			} else {
				if response.Parent == "pages" && response.Name == "index" && response.Ext == ".html" {
					outputDir = path.Join(sitePrefix, "output")
				} else {
					outputDir = path.Join(sitePrefix, "output", tail, response.Name)
				}
			}
			tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			var uploadCount, uploadSize atomic.Int64
			writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
				writerCtx, cancelWriter := context.WithCancel(ctx)
				defer cancelWriter()
				writer, err := nbrew.FS.WithContext(writerCtx).OpenWriter(filePath, 0644)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
					err := nbrew.FS.WithContext(writerCtx).MkdirAll(path.Dir(filePath), 0755)
					if err != nil {
						return err
					}
					writer, err = nbrew.FS.WithContext(writerCtx).OpenWriter(filePath, 0644)
					if err != nil {
						return err
					}
				}
				defer func() {
					cancelWriter()
					writer.Close()
				}()
				var n int64
				if storageRemaining != nil {
					limitedWriter := &LimitedWriter{
						W:   writer,
						N:   storageRemaining.Load(),
						Err: ErrStorageLimitExceeded,
					}
					n, err = io.Copy(limitedWriter, reader)
					storageRemaining.Add(-n)
				} else {
					n, err = io.Copy(writer, reader)
				}
				if err != nil {
					return stacktrace.New(err)
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				uploadCount.Add(1)
				uploadSize.Add(n)
				return nil
			}
			var monotonicCounter atomic.Int64
			group, groupctx := errgroup.WithContext(r.Context())
			for {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				if formName != "file" {
					continue
				}
				_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
				if err != nil {
					continue
				}
				fileName := params["filename"]
				if fileName == "" || strings.Contains(fileName, "/") {
					continue
				}
				fileName = filenameSafe(fileName)
				fileType := AllowedFileTypes[path.Ext(fileName)]
				switch head {
				case "pages":
					if !fileType.Has(AttributeImg) && !fileType.Has(AttributeVideo) && fileType.Ext != ".css" && fileType.Ext != ".js" && fileType.Ext != ".md" {
						continue
					}
				case "posts":
					if !fileType.Has(AttributeImg) && !fileType.Has(AttributeVideo) {
						continue
					}
				}
				if fileType.Has(AttributeImg) {
					if user.UserFlags["NoUploadImage"] {
						continue
					}
					if strings.TrimSuffix(fileName, fileType.Ext) == "image" {
						var timestamp [8]byte
						now := time.Now()
						monotonicCounter.CompareAndSwap(0, now.Unix())
						binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), monotonicCounter.Add(1))))
						timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
						fileName = "image-" + timestampSuffix + fileType.Ext
					}
					filePath := path.Join(outputDir, fileName)
					if !fileType.Has(AttributeObject) {
						err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
						if err != nil {
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								response.FilesTooBig = append(response.FilesTooBig, fileName)
								continue
							}
							if errors.Is(err, ErrStorageLimitExceeded) {
								nbrew.StorageLimitExceeded(w, r)
								return
							}
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
					} else {
						if nbrew.LossyImgCmd == "" {
							err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
							if err != nil {
								var maxBytesErr *http.MaxBytesError
								if errors.As(err, &maxBytesErr) {
									response.FilesTooBig = append(response.FilesTooBig, fileName)
									continue
								}
								if errors.Is(err, ErrStorageLimitExceeded) {
									nbrew.StorageLimitExceeded(w, r)
									return
								}
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
						} else {
							cmdPath, err := exec.LookPath(nbrew.LossyImgCmd)
							if err != nil {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
							id := NewID()
							inputPath := path.Join(tempDir, id.String()+"-input"+fileType.Ext)
							outputPath := path.Join(tempDir, id.String()+"-output"+fileType.Ext)
							input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
							if err != nil {
								if !errors.Is(err, fs.ErrNotExist) {
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
								err := os.MkdirAll(filepath.Dir(inputPath), 0755)
								if err != nil {
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
								input, err = os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
								if err != nil {
									nbrew.GetLogger(r.Context()).Error(err.Error())
									nbrew.InternalServerError(w, r, err)
									return
								}
							}
							_, err = io.Copy(input, http.MaxBytesReader(nil, part, fileType.SizeLimit))
							if err != nil {
								os.Remove(inputPath)
								var maxBytesErr *http.MaxBytesError
								if errors.As(err, &maxBytesErr) {
									response.FilesTooBig = append(response.FilesTooBig, fileName)
									continue
								}
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
							err = input.Close()
							if err != nil {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
							group.Go(func() (err error) {
								defer stacktrace.RecoverPanic(&err)
								defer os.Remove(inputPath)
								defer os.Remove(outputPath)
								cmd := exec.CommandContext(groupctx, cmdPath, inputPath, outputPath)
								cmd.Stdout = os.Stdout
								cmd.Stderr = os.Stderr
								err = cmd.Run()
								if err != nil {
									return stacktrace.New(err)
								}
								output, err := os.Open(outputPath)
								if err != nil {
									return err
								}
								defer output.Close()
								err = writeFile(groupctx, filePath, output)
								if err != nil {
									return err
								}
								return nil
							})
						}
					}
				} else if fileType.Has(AttributeVideo) {
					if user.UserFlags["NoUploadVideo"] {
						continue
					}
					if strings.TrimSuffix(fileName, fileType.Ext) == "video" {
						var timestamp [8]byte
						now := time.Now()
						monotonicCounter.CompareAndSwap(0, now.Unix())
						binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), monotonicCounter.Add(1))))
						timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
						fileName = "image-" + timestampSuffix + fileType.Ext
					}
					filePath := path.Join(outputDir, fileName)
					if nbrew.VideoCmd == "" {
						err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
						if err != nil {
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								response.FilesTooBig = append(response.FilesTooBig, fileName)
								continue
							}
							if errors.Is(err, ErrStorageLimitExceeded) {
								nbrew.StorageLimitExceeded(w, r)
								return
							}
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
					} else {
						cmdPath, err := exec.LookPath(nbrew.VideoCmd)
						if err != nil {
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
						id := NewID()
						inputPath := path.Join(tempDir, id.String()+"-input"+fileType.Ext)
						outputPath := path.Join(tempDir, id.String()+"-output"+fileType.Ext)
						input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
						if err != nil {
							if !errors.Is(err, fs.ErrNotExist) {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
							err := os.MkdirAll(filepath.Dir(inputPath), 0755)
							if err != nil {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
							input, err = os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
							if err != nil {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
						}
						_, err = io.Copy(input, http.MaxBytesReader(nil, part, fileType.SizeLimit))
						if err != nil {
							os.Remove(inputPath)
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								response.FilesTooBig = append(response.FilesTooBig, fileName)
								continue
							}
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
						err = input.Close()
						if err != nil {
							nbrew.GetLogger(r.Context()).Error(err.Error())
							nbrew.InternalServerError(w, r, err)
							return
						}
						group.Go(func() (err error) {
							defer stacktrace.RecoverPanic(&err)
							defer os.Remove(inputPath)
							defer os.Remove(outputPath)
							cmd := exec.CommandContext(groupctx, cmdPath, inputPath, outputPath)
							cmd.Stdout = os.Stdout
							cmd.Stderr = os.Stderr
							err = cmd.Run()
							if err != nil {
								return stacktrace.New(err)
							}
							output, err := os.Open(outputPath)
							if err != nil {
								return err
							}
							defer output.Close()
							err = writeFile(groupctx, filePath, output)
							if err != nil {
								return err
							}
							return nil
						})
					}
				} else {
					filePath := path.Join(outputDir, fileName)
					err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
					if err != nil {
						var maxBytesErr *http.MaxBytesError
						if errors.As(err, &maxBytesErr) {
							response.FilesTooBig = append(response.FilesTooBig, fileName)
							continue
						}
						if errors.Is(err, ErrStorageLimitExceeded) {
							nbrew.StorageLimitExceeded(w, r)
							return
						}
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
				}
			}
			err = group.Wait()
			if err != nil {
				if errors.Is(err, ErrStorageLimitExceeded) {
					nbrew.StorageLimitExceeded(w, r)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.UploadCount = uploadCount.Load()
			response.UploadSize = uploadSize.Load()
		}

		switch head {
		case "pages":
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
			startedAt := time.Now()
			err = siteGen.GeneratePage(r.Context(), path.Join(response.Parent, response.Name+response.Ext), response.Content, startedAt, startedAt)
			if err != nil {
				if !errors.As(err, &response.RegenerationStats.TemplateError) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			}
			response.RegenerationStats.Count = 1
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
		case "posts":
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
			var regenerationCount atomic.Int64
			var templateErrPtr atomic.Pointer[TemplateError]
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var templateErr TemplateError
				category := tail
				tmpl, err := siteGen.PostTemplate(groupctx, category)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				filePath := path.Join(response.Parent, response.Name+response.Ext)
				creationTime := time.Now()
				err = siteGen.GeneratePost(groupctx, filePath, response.Content, creationTime, creationTime, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				regenerationCount.Add(1)
				return nil
			})
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var templateErr TemplateError
				category := tail
				tmpl, err := siteGen.PostListTemplate(groupctx, category)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				n, err := siteGen.GeneratePostList(r.Context(), category, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				regenerationCount.Add(int64(n))
				return nil
			})
			err = group.Wait()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = regenerationCount.Load()
			if templateErrPtr.Load() != nil {
				response.RegenerationStats.TemplateError = *templateErrPtr.Load()
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next != "posts" && next != "themes" && response.Ext == ".md" {
				var parentPage string
				if tail == "" {
					parentPage = "pages/index.html"
				} else {
					parentPage = path.Join("pages", tail+".html")
				}
				file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, parentPage))
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				fileInfo, err := file.Stat()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
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
				startedAt := time.Now()
				err = siteGen.GeneratePage(r.Context(), parentPage, b.String(), startedAt, startedAt)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count = 1
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
