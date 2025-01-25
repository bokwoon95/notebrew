package notebrew

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) delet(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		Size         int64     `json:"size"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Request struct {
		Parent string   `json:"parent"`
		Names  []string `json:"names"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		CDNDomain         string            `json:"cdnDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		Parent            string            `json:"parent"`
		Files             []File            `json:"files"`
		Error             string            `json:"error"`
		DeleteErrors      []string          `json:"deleteErrors"`
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
				"join":                  path.Join,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"getFileType": func(name string) FileType {
					return AllowedFileTypes[strings.ToLower(path.Ext(name))]
				},
			}
			tmpl, err := template.New("delete.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/delete.html")
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
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages", "posts", "output", "imports", "exports":
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
		seen := make(map[string]bool)
		group, groupctx := errgroup.WithContext(r.Context())
		names := r.Form["name"]
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
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
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "delete")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":         "delete",
					"numDeleted":   len(response.Files),
					"deleteErrors": response.DeleteErrors,
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			head, tail, _ := strings.Cut(response.Parent, "/")
			if head != "output" {
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
				return
			}
			next, _, _ := strings.Cut(tail, "/")
			switch next {
			case "themes":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
				return
			case "posts":
				_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, tail+".md"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, tail+".md"), http.StatusFound)
				return
			case "":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "pages/index.html"), http.StatusFound)
				return
			default:
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "pages", tail+".html"), http.StatusFound)
				return
			}
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
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		var response Response
		response.Parent = path.Clean(strings.Trim(request.Parent, "/"))
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages", "posts", "output", "imports", "exports":
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
		seen := make(map[string]bool)
		n := 0
		for _, name := range request.Names {
			name := filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			request.Names[n] = name
			n++
		}
		request.Names = request.Names[:n]
		slices.Sort(request.Names)

		// Deleting the output files sounds deceptively simple (it's bloody complicated).
		// 1. delete files
		// 2. delete outputDir (if an entire post category was deleted, we also delete the entire output/posts/{category})
		// 3. if index.html or 404.html was deleted, restore it with embed/index.html or embed/404.html and regenerate the pages
		// 4. if post.html was deleted, restore it in with embed/post.html and regenerate all posts for the category
		// 5. if postlist.html was deleted, restore it with embed/postlist.html and regenerate the postlist for the category
		// 6. if postlist.json was deleted, restore it with embed/postlist.json and regenerate the postlist for the category
		// 7. if a post was deleted, regenerate the postlist for the category
		// 8. if a page was deleted, regenerate the parent page
		// 9. if a page asset (markdown file or image) was deleted, regenerate the parent page
		// 10. if a post image was deleted, regenerate the parent post
		type deleteAction int
		const (
			deleteFiles       deleteAction = 1 << 0
			deleteDirectories deleteAction = 1 << 1
		)
		var (
			outputDirsToDelete            = make(map[string]deleteAction)
			outputDirsToDeleteMutex       = sync.Mutex{}
			restoreAndRegenerateIndexHTML atomic.Bool
			restoreAndRegenerate404HTML   atomic.Bool
			restoreCategoryPostHTML       atomic.Pointer[string]
			restoreCategoryPostListHTML   atomic.Pointer[string]
			restoreCategoryPostListJSON   atomic.Pointer[string]
			regenerateCategoryPosts       atomic.Pointer[string]
			regenerateCategoryPostList    atomic.Pointer[string]
			regenerateParentPage          atomic.Pointer[string]
			regenerateParentPost          atomic.Pointer[string]
		)
		head, tail, _ := strings.Cut(response.Parent, "/")
		groupA, groupctxA := errgroup.WithContext(r.Context())
		response.DeleteErrors = make([]string, len(request.Names))
		response.Files = make([]File, len(request.Names))
		for i, name := range request.Names {
			i, name := i, name
			groupA.Go(func() error {
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctxA), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				isDir := fileInfo.IsDir()
				err = nbrew.FS.WithContext(groupctxA).RemoveAll(path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					response.DeleteErrors[i] = err.Error()
					return nil
				}
				response.Files[i] = File{Name: name}
				switch head {
				case "pages":
					if isDir {
						outputDir := path.Join("output", tail, name)
						outputDirsToDeleteMutex.Lock()
						outputDirsToDelete[outputDir] |= deleteDirectories
						outputDirsToDeleteMutex.Unlock()
					} else {
						if tail == "" {
							if name == "index.html" {
								outputDir := "output"
								outputDirsToDeleteMutex.Lock()
								outputDirsToDelete[outputDir] |= deleteFiles
								outputDirsToDeleteMutex.Unlock()
								restoreAndRegenerateIndexHTML.Store(true)
							} else {
								outputDir := path.Join("output", strings.TrimSuffix(name, ".html"))
								outputDirsToDeleteMutex.Lock()
								outputDirsToDelete[outputDir] |= deleteFiles
								outputDirsToDeleteMutex.Unlock()
								if name == "404.html" {
									restoreAndRegenerate404HTML.Store(true)
								} else {
									parentPage := "pages/index.html"
									regenerateParentPage.Store(&parentPage)
								}
							}
						} else {
							outputDir := path.Join("output", tail, strings.TrimSuffix(name, ".html"))
							outputDirsToDeleteMutex.Lock()
							outputDirsToDelete[outputDir] |= deleteFiles
							outputDirsToDeleteMutex.Unlock()
							parentPage := response.Parent + ".html"
							regenerateParentPage.Store(&parentPage)
						}
					}
				case "posts":
					if isDir {
						if tail == "" {
							category := name
							outputDir := path.Join("output/posts", category)
							outputDirsToDeleteMutex.Lock()
							outputDirsToDelete[outputDir] |= deleteDirectories
							outputDirsToDeleteMutex.Unlock()
						}
					} else {
						if !strings.Contains(tail, "/") {
							category := tail
							if strings.HasSuffix(name, ".md") {
								outputDir := path.Join("output/posts", tail, strings.TrimSuffix(name, ".md"))
								outputDirsToDeleteMutex.Lock()
								outputDirsToDelete[outputDir] |= deleteFiles
								outputDirsToDeleteMutex.Unlock()
								regenerateCategoryPostList.Store(&category)
							} else if name == "post.html" {
								restoreCategoryPostHTML.Store(&category)
								regenerateCategoryPosts.Store(&category)
							} else if name == "postlist.html" {
								restoreCategoryPostListHTML.Store(&category)
								regenerateCategoryPostList.Store(&category)
							} else if name == "postlist.json" {
								restoreCategoryPostListJSON.Store(&category)
								regenerateCategoryPostList.Store(&category)
							}
						}
					}
				case "output":
					if !isDir {
						next, _, _ := strings.Cut(tail, "/")
						fileType := AllowedFileTypes[strings.ToLower(path.Ext(name))]
						if next == "posts" {
							if fileType.Has(AttributeImg) || fileType.Has(AttributeVideo) {
								parentPost := tail + ".md"
								regenerateParentPost.Store(&parentPost)
							}
						} else if next != "themes" {
							if fileType.Has(AttributeImg) || fileType.Has(AttributeVideo) || fileType.Ext == ".md" {
								var parentPage string
								if tail == "" {
									parentPage = "pages/index.html"
								} else {
									parentPage = path.Join("pages", tail+".html")
								}
								regenerateParentPage.Store(&parentPage)
							}
						}
					}
				}
				return nil
			})
		}
		err := groupA.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}

		groupB, groupctxB := errgroup.WithContext(r.Context())
		for outputDir, deleteAction := range outputDirsToDelete {
			outputDir, deleteAction := outputDir, deleteAction
			groupB.Go(func() error {
				if deleteAction == 0 {
					return nil
				}
				head, tail, _ := strings.Cut(outputDir, "/")
				if head != "output" {
					nbrew.GetLogger(groupctxB).Error(fmt.Sprintf("programmer error: attempted to delete output directory %s (which is not an output directory)", outputDir))
					return nil
				}
				nextHead, nextTail, _ := strings.Cut(tail, "/")
				if nextTail == "" {
					if nextHead == "posts" {
						nbrew.GetLogger(groupctxB).Error(fmt.Sprintf("programmer error: attempted to delete output/posts wholesale"))
						return nil
					}
					if nextHead == "themes" {
						nbrew.GetLogger(groupctxB).Error(fmt.Sprintf("programmer error: attempted to delete output/themes wholesale"))
						return nil
					}
				}
				if deleteAction&deleteFiles != 0 && deleteAction&deleteDirectories != 0 {
					return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
				}
				if deleteAction&deleteFiles != 0 {
					if nextTail != "" {
						var counterpart string
						if nextHead == "posts" {
							counterpart = path.Join(sitePrefix, "posts", nextTail)
						} else {
							counterpart = path.Join(sitePrefix, "pages", nextTail)
						}
						fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctxB), counterpart)
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							} else {
								return err
							}
						} else {
							if !fileInfo.IsDir() {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							}
						}
					}
					dirEntries, err := nbrew.FS.WithContext(groupctxB).ReadDir(path.Join(sitePrefix, outputDir))
					if err != nil {
						return err
					}
					subgroup, subctx := errgroup.WithContext(groupctxB)
					for _, dirEntry := range dirEntries {
						if dirEntry.IsDir() {
							continue
						}
						name := dirEntry.Name()
						subgroup.Go(func() (err error) {
							defer stacktrace.RecoverPanic(&err)
							return nbrew.FS.WithContext(subctx).RemoveAll(path.Join(sitePrefix, outputDir, name))
						})
					}
					return subgroup.Wait()
				}
				if deleteAction&deleteDirectories != 0 {
					if tail != "" {
						var counterpart string
						if head == "posts" {
							counterpart = path.Join(sitePrefix, "posts", tail+".md")
						} else {
							counterpart = path.Join(sitePrefix, "pages", tail+".html")
						}
						fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctxB), counterpart)
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							} else {
								return err
							}
						} else {
							if fileInfo.IsDir() {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							}
						}
					}
					dirEntries, err := nbrew.FS.WithContext(groupctxB).ReadDir(path.Join(sitePrefix, outputDir))
					if err != nil {
						return err
					}
					subgroup, subctx := errgroup.WithContext(groupctxB)
					for _, dirEntry := range dirEntries {
						if !dirEntry.IsDir() {
							continue
						}
						name := dirEntry.Name()
						subgroup.Go(func() (err error) {
							defer stacktrace.RecoverPanic(&err)
							return nbrew.FS.WithContext(subctx).RemoveAll(path.Join(sitePrefix, outputDir, name))
						})
					}
					return subgroup.Wait()
				}
				return nil
			})
		}
		err = groupB.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}

		groupC, groupctxC := errgroup.WithContext(r.Context())
		var indexHTML string
		if restoreAndRegenerateIndexHTML.Load() {
			groupC.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/index.html")
				if err != nil {
					return err
				}
				indexHTML = string(b)
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		var x404HTML string
		if restoreAndRegenerate404HTML.Load() {
			groupC.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/404.html")
				if err != nil {
					return err
				}
				x404HTML = string(b)
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		if restoreCategoryPostHTML.Load() != nil {
			groupC.Go(func() error {
				category := *restoreCategoryPostHTML.Load()
				b, err := fs.ReadFile(RuntimeFS, "embed/post.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "posts", category, "post.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		if restoreCategoryPostListHTML.Load() != nil {
			groupC.Go(func() error {
				category := *restoreCategoryPostListHTML.Load()
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "posts", category, "postlist.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		if restoreCategoryPostListJSON.Load() != nil {
			groupC.Go(func() error {
				category := *restoreCategoryPostListJSON.Load()
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.json")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "posts", category, "postlist.json"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		err = groupC.Wait()
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}

		if restoreAndRegenerateIndexHTML.Load() ||
			restoreAndRegenerate404HTML.Load() ||
			regenerateCategoryPosts.Load() != nil ||
			regenerateCategoryPostList.Load() != nil ||
			regenerateParentPage.Load() != nil ||
			regenerateParentPost.Load() != nil {
			var templateErrPtr atomic.Pointer[TemplateError]
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
			regenerationCount := atomic.Int64{}
			startedAt := time.Now()
			groupD, groupctxD := errgroup.WithContext(r.Context())
			if restoreAndRegenerateIndexHTML.Load() {
				groupD.Go(func() error {
					creationTime := time.Now()
					err := siteGen.GeneratePage(groupctxD, "pages/index.html", indexHTML, creationTime, creationTime)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			if restoreAndRegenerate404HTML.Load() {
				groupD.Go(func() error {
					creationTime := time.Now()
					err := siteGen.GeneratePage(groupctxD, "pages/404.html", x404HTML, creationTime, creationTime)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			if regenerateCategoryPosts.Load() != nil {
				groupD.Go(func() error {
					category := *regenerateCategoryPosts.Load()
					tmpl, err := siteGen.PostTemplate(groupctxD, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					n, err := siteGen.GeneratePosts(groupctxD, category, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(int64(n))
					return nil
				})
			}
			if regenerateCategoryPostList.Load() != nil {
				groupD.Go(func() error {
					category := *regenerateCategoryPostList.Load()
					tmpl, err := siteGen.PostListTemplate(groupctxD, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					n, err := siteGen.GeneratePostList(groupctxD, category, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(int64(n))
					return nil
				})
			}
			if regenerateParentPage.Load() != nil {
				groupD.Go(func() error {
					filePath := *regenerateParentPage.Load()
					file, err := nbrew.FS.WithContext(groupctxD).Open(path.Join(sitePrefix, filePath))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							return nil
						}
						return err
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						return err
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						return err
					}
					creationTime := time.Now()
					err = siteGen.GeneratePage(groupctxD, filePath, b.String(), creationTime, creationTime)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			if regenerateParentPost.Load() != nil {
				groupD.Go(func() error {
					filePath := *regenerateParentPost.Load()
					category := path.Dir(strings.TrimPrefix(filePath, "posts/"))
					if category == "." {
						category = ""
					}
					tmpl, err := siteGen.PostTemplate(groupctxD, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					file, err := nbrew.FS.WithContext(groupctxD).Open(path.Join(sitePrefix, filePath))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							return nil
						}
						return err
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						return err
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						return err
					}
					var creationTime time.Time
					if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
						creationTime = databaseFileInfo.CreationTime
					} else {
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
							}
						}
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					err = siteGen.GeneratePost(groupctxD, filePath, b.String(), time.Now(), creationTime, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			err = groupD.Wait()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = regenerationCount.Load()
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			if templateErrPtr.Load() != nil {
				response.RegenerationStats.TemplateError = *templateErrPtr.Load()
			}
		}

		n = 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		n = 0
		for _, errmsg := range response.DeleteErrors {
			if errmsg == "" {
				continue
			}
			response.DeleteErrors[n] = errmsg
			n++
		}
		response.DeleteErrors = response.DeleteErrors[:n]
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
