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
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) uploadfile(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		Error             string            `json:"error"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		Parent            string            `json:"parent"`
		UploadCount       int64             `json:"uploadCount"`
		UploadSize        int64             `json:"uploadSize"`
		FilesExist        []string          `json:"fileExist"`
		FilesTooBig       []string          `json:"filesTooBig"`
	}
	if r.Method != "POST" {
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
		err := nbrew.SetFlashSession(w, r, map[string]any{
			"postRedirectGet": map[string]any{
				"from":              "uploadfile",
				"regenerationStats": response.RegenerationStats,
				"error":             response.Error,
				"uploadCount":       response.UploadCount,
				"uploadSize":        response.UploadSize,
				"filesExist":        response.FilesExist,
				"filesTooBig":       response.FilesTooBig,
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
	}

	reader, err := r.MultipartReader()
	if err != nil {
		if errors.Is(err, http.ErrNotMultipart) {
			nbrew.UnsupportedContentType(w, r)
			return
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	var response Response
	part, err := reader.NextPart()
	if err != nil {
		if err == io.EOF {
			response.Error = "ParentNotFound"
			writeResponse(w, r, response)
			return
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	formName := part.FormName()
	if formName != "parent" {
		response.Error = "ParentNotFound"
		writeResponse(w, r, response)
		return
	}
	var b strings.Builder
	_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			nbrew.BadRequest(w, r, err)
			return
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	response.Parent = b.String()

	var siteGen *SiteGenerator
	var postTemplate *template.Template
	var templateErrPtr atomic.Pointer[TemplateError]
	head, tail, _ := strings.Cut(response.Parent, "/")
	switch head {
	case "notes":
		break
	case "pages":
		siteGen, err = NewSiteGenerator(r.Context(), SiteGeneratorConfig{
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
	case "posts":
		siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
			FS:                 nbrew.FS,
			ContentDomain:      nbrew.ContentDomain,
			ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
			CDNDomain:          nbrew.CDNDomain,
			SitePrefix:         sitePrefix,
		})
		category := tail
		postTemplate, err = siteGen.PostTemplate(r.Context(), category)
		if err != nil {
			var templateErr TemplateError
			if !errors.As(err, &templateErr) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			templateErrPtr.CompareAndSwap(nil, &templateErr)
		}
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		if next != "themes" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
	case "imports":
		break
	default:
		response.Error = "InvalidParent"
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

	var regenerationCount, uploadCount, uploadSize atomic.Int64
	writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
		writerCtx, cancelWriter := context.WithCancel(ctx)
		defer cancelWriter()
		writer, err := nbrew.FS.WithContext(writerCtx).OpenWriter(filePath, 0644)
		if err != nil {
			return stacktrace.New(err)
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
			return stacktrace.New(err)
		}
		uploadCount.Add(1)
		uploadSize.Add(n)
		return nil
	}

	tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	var monotonicCounter atomic.Int64
	group, groupctx := errgroup.WithContext(r.Context())
	startedAt := time.Now()
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
		fileType := AllowedFileTypes[strings.ToLower(path.Ext(fileName))]
		if fileType.Has(AttributeImg) && strings.TrimSuffix(fileName, fileType.Ext) == "image" {
			var timestamp [8]byte
			now := time.Now()
			monotonicCounter.CompareAndSwap(0, now.Unix())
			binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), monotonicCounter.Add(1))))
			timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			fileName = "image-" + timestampSuffix + fileType.Ext
		}
		filePath := path.Join(sitePrefix, response.Parent, fileName)
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), filePath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			response.FilesExist = append(response.FilesExist, fileName)
			continue
		}

		switch head {
		case "notes":
			if fileType.Has(AttributeEditable) || fileType.Has(AttributeImg) || fileType.Has(AttributeVideo) || fileType.Has(AttributeFont) {
				if fileType.Has(AttributeImg) && user.UserFlags["NoUploadImage"] {
					continue
				}
				if fileType.Has(AttributeVideo) {
					if user.UserFlags["NoUploadVideo"] {
						continue
					}
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
								return stacktrace.New(err)
							}
							err = writeFile(groupctx, filePath, output)
							if err != nil {
								return err
							}
							return nil
						})
					}
					continue
				}
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
		case "pages":
			if fileType.Ext != ".html" {
				continue
			}
			if tail == "" && (fileName == "posts.html" || fileName == "themes.html") {
				continue
			}
			var b strings.Builder
			_, err := io.Copy(&b, http.MaxBytesReader(nil, part, fileType.SizeLimit))
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					response.FilesTooBig = append(response.FilesTooBig, fileName)
					continue
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			text := b.String()
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				err = writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				creationTime := time.Now()
				err = siteGen.GeneratePage(groupctx, filePath, text, creationTime, creationTime)
				if err != nil {
					var templateErr TemplateError
					if !errors.As(err, &templateErr) {
						return err
					}
					templateErrPtr.CompareAndSwap(nil, &templateErr)
				}
				regenerationCount.Add(1)
				return nil
			})
		case "posts":
			if fileType.Ext != ".md" {
				if fileName == "postlist.json" || fileName == "postlist.html" || fileName == "post.html" {
					err := writeFile(groupctx, filePath, http.MaxBytesReader(nil, part, fileType.SizeLimit))
					if err != nil {
						var maxBytesErr *http.MaxBytesError
						if errors.As(err, &maxBytesErr) {
							response.FilesTooBig = append(response.FilesTooBig, fileName)
							continue
						}
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
				}
				continue
			}
			var b strings.Builder
			_, err := io.Copy(&b, http.MaxBytesReader(nil, part, fileType.SizeLimit))
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					response.FilesTooBig = append(response.FilesTooBig, fileName)
					continue
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			text := b.String()
			now := time.Now()
			monotonicCounter.CompareAndSwap(0, now.Unix())
			creationTime := time.Unix(max(now.Unix(), monotonicCounter.Add(1)), 0).UTC()
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(creationTime.Unix()))
				prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
				if strings.TrimSuffix(fileName, fileType.Ext) != "" {
					fileName = prefix + "-" + fileName
				} else {
					fileName = prefix + fileName
				}
				filePath := path.Join(sitePrefix, response.Parent, fileName)
				err = writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePost(groupctx, filePath, text, creationTime, creationTime, postTemplate)
				if err != nil {
					var templateErr TemplateError
					if !errors.As(err, &templateErr) {
						return stacktrace.New(err)
					}
					templateErrPtr.CompareAndSwap(nil, &templateErr)
				}
				regenerationCount.Add(1)
				return nil
			})
		case "output":
			if fileType.Has(AttributeEditable) || fileType.Has(AttributeFont) {
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
			} else if fileType.Has(AttributeImg) {
				if user.UserFlags["NoUploadImage"] {
					continue
				}
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
								return stacktrace.New(err)
							}
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
							return stacktrace.New(err)
						}
						err = writeFile(groupctx, filePath, output)
						if err != nil {
							return err
						}
						return nil
					})
				}
			}
		case "imports":
			if fileType.Ext != ".tgz" {
				continue
			}
			err := writeFile(r.Context(), filePath, part)
			if err != nil {
				if errors.Is(err, ErrStorageLimitExceeded) {
					nbrew.StorageLimitExceeded(w, r)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		default:
			panic("unreachable")
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
	timeTaken := time.Since(startedAt)
	if head == "posts" {
		category := tail
		err := func() error {
			postListTemplate, err := siteGen.PostListTemplate(r.Context(), category)
			if err != nil {
				return err
			}
			_, err = siteGen.GeneratePostList(r.Context(), category, postListTemplate)
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			var templateErr TemplateError
			if !errors.As(err, &templateErr) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			templateErrPtr.CompareAndSwap(nil, &templateErr)
		}
	}
	response.UploadCount = uploadCount.Load()
	response.UploadSize = uploadSize.Load()
	response.RegenerationStats.Count = regenerationCount.Load()
	if response.RegenerationStats.Count != 0 {
		response.RegenerationStats.TimeTaken = timeTaken.String()
	}
	if templateErrPtr.Load() != nil {
		response.RegenerationStats.TemplateError = *templateErrPtr.Load()
	}
	writeResponse(w, r, response)
}
