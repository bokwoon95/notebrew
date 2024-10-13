package notebrew

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template/parse"
	"time"

	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/bokwoon95/notebrew/internal/highlighting"
	"github.com/bokwoon95/notebrew/internal/markdownmath"
	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/davecgh/go-spew/spew"
	"github.com/jdkato/prose/transform"
	fences "github.com/stefanfritsch/goldmark-fences"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"
)

// SiteGenerator is used to generate pages and posts for a particular site.
type SiteGenerator struct {
	// Site information.
	Site Site

	// fsys is the FS to generate pages and posts in.
	fsys FS

	// sitePrefix is the site prefix.
	sitePrefix string

	// contentDomain is the domain that the site's generated content is served
	// on.
	contentDomain string

	// contentDomainHTTPS indicates whether the content domain is served over
	// HTTPS.
	contentDomainHTTPS bool

	// cdnDomain is the domain of the CDN that is used for hosting images.
	cdnDomain string

	// markdown is the goldmark parser and renderer used to generate from the
	// site's markdown files.
	markdown goldmark.Markdown

	// funcMap stores the template funcMap used by the site's templates.
	funcMap map[string]any

	// mutex is used to guard access to templateCache, templateInProgress and
	// imgFileIDs.
	mutex sync.Mutex

	// templateCache caches already-parsed templates, keyed by their file path
	// (relative to the sitePrefix).
	templateCache map[string]*template.Template

	// templateInProgress stores wait channels of the templates whose parsing
	// are currently in progress. If a wait channel is present, all code
	// looking to parse a template should wait until the channel returns, then
	// check the template cache for the already-parsed template. This ensures
	// that goroutines do not parse the same template twice -- one goroutine
	// will always parse the templates first, the rest will wait for the result
	// and fetch it from the templateCache map.
	templateInProgress map[string]chan struct{}

	// imgFileIDs stores a mapping of image file paths to their file IDs. This
	// is used for rewriting image URLs into their CDN links, which references
	// images by their file IDs.
	imgFileIDs map[string]ID
}

// NavigationLink represents a navigation link to be displayed in the site's
// navigation menu.
type NavigationLink struct {
	// Name of the link.
	Name string

	// URL of the link.
	URL string
}

// Site holds the global properties of a site.
type Site struct {
	// Language code of the site.
	LanguageCode string

	// Title of the site.
	Title string

	// Tagline of the site.
	Tagline string

	// Favicon of the site.
	Favicon template.URL

	// The site's timezone offset in seconds.
	TimezoneOffsetSeconds int

	// Description of the site.
	Description string

	// NavigationLinks of the site.
	NavigationLinks []NavigationLink
}

// SiteGeneratorConfig holds the parameters needed to construct a new SiteGenerator.
type SiteGeneratorConfig struct {
	// FS is the filesystem that holds the site content.
	FS FS

	// ContentDomain is the domain that the site's generated content is served
	// on.
	ContentDomain string

	// ContentDomainHTTPS indicates whether the content domain is served over
	// HTTPS.
	ContentDomainHTTPS bool

	// CDNDomain is the domain of the CDN that is used for hosting images.
	CDNDomain string

	// SitePrefix is the site prefix of the site.
	SitePrefix string
}

// NewSiteGenerator constructs a new SiteGenerator.
func NewSiteGenerator(ctx context.Context, siteGenConfig SiteGeneratorConfig) (*SiteGenerator, error) {
	siteGen := &SiteGenerator{
		fsys:               siteGenConfig.FS,
		sitePrefix:         siteGenConfig.SitePrefix,
		contentDomain:      siteGenConfig.ContentDomain,
		contentDomainHTTPS: siteGenConfig.ContentDomainHTTPS,
		cdnDomain:          siteGenConfig.CDNDomain,
		funcMap:            map[string]any{},
		mutex:              sync.Mutex{},
		templateCache:      make(map[string]*template.Template),
		templateInProgress: make(map[string]chan struct{}),
	}
	var config struct {
		LanguageCode    string
		Title           string
		Tagline         string
		Emoji           string
		Favicon         string
		CodeStyle       string
		TimezoneOffset  string
		Description     string
		NavigationLinks []NavigationLink
	}
	// Read from the site's site.json.
	b, err := fs.ReadFile(siteGen.fsys, path.Join(siteGen.sitePrefix, "site.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, stacktrace.New(err)
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &config)
		if err != nil {
			fmt.Printf("%s\n", string(b))
			return nil, stacktrace.New(err)
		}
	} else {
		config.Emoji = "☕"
		config.NavigationLinks = []NavigationLink{
			{Name: "Home", URL: "/"},
			{Name: "Posts", URL: "/posts/"},
		}
	}
	if config.LanguageCode == "" {
		config.LanguageCode = "en"
	}
	if config.Favicon == "" {
		emoji := config.Emoji
		if emoji == "" {
			emoji = "☕"
		}
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + emoji + "</text></svg>"
	}
	if config.CodeStyle == "" {
		config.CodeStyle = "onedark"
	}
	// Prepare the site's markdown parser and renderer based on their code
	// syntax highlighter style.
	siteGen.markdown = goldmark.New(
		goldmark.WithParserOptions(
			parser.WithAttribute(),
		),
		goldmark.WithExtensions(
			highlighting.NewHighlighting(
				highlighting.WithStyle(config.CodeStyle),
				highlighting.WithFormatOptions(chromahtml.TabWidth(2)),
			),
			extension.Footnote,
			extension.CJK,
			markdownmath.Extension,
			&fences.Extender{},
		),
		goldmark.WithRendererOptions(
			goldmarkhtml.WithHardWraps(),
			goldmarkhtml.WithUnsafe(),
		),
	)
	for name, fn := range baseFuncMap {
		siteGen.funcMap[name] = fn
	}
	siteGen.funcMap["markdownToHTML"] = func(x any) (template.HTML, error) {
		if s, ok := x.(string); ok {
			var b strings.Builder
			err := siteGen.markdown.Convert([]byte(s), &b)
			if err != nil {
				return "", err
			}
			return template.HTML(b.String()), nil
		}
		return "", fmt.Errorf("%#v is not a string", x)
	}
	siteGen.funcMap["markdownTextOnly"] = func(x any) (string, error) {
		if s, ok := x.(string); ok {
			return markdownTextOnly(siteGen.markdown.Parser(), []byte(s)), nil
		}
		return "", fmt.Errorf("%#v is not a string", x)
	}
	var timezoneOffsetSeconds int
	if strings.HasPrefix(config.TimezoneOffset, "+") || strings.HasPrefix(config.TimezoneOffset, "-") {
		before, after, ok := strings.Cut(config.TimezoneOffset, ":")
		hours, err := strconv.Atoi(before)
		if err == nil && hours >= -12 && hours <= 14 {
			if ok {
				minutes, err := strconv.Atoi(after)
				if err == nil && minutes >= 0 && minutes <= 59 {
					timezoneOffsetSeconds = ((hours * 60) + minutes) * 60
				}
			} else {
				timezoneOffsetSeconds = hours * 60 * 60
			}
		}
	}
	siteGen.Site = Site{
		LanguageCode:          config.LanguageCode,
		Title:                 config.Title,
		Tagline:               config.Tagline,
		Favicon:               template.URL(config.Favicon),
		TimezoneOffsetSeconds: timezoneOffsetSeconds,
		NavigationLinks:       config.NavigationLinks,
	}
	if config.Description != "" {
		siteGen.Site.Description = config.Description
	}
	if siteGen.cdnDomain == "" {
		return siteGen, nil
	}
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	if !isDatabaseFS {
		return siteGen, nil
	}
	extFilter := sq.Expr("1 = 1")
	if len(imgExts) > 0 {
		var b strings.Builder
		args := make([]any, 0, len(imgExts))
		b.WriteString("(")
		for i, ext := range imgExts {
			if i > 0 {
				b.WriteString(" OR ")
			}
			b.WriteString("file_path LIKE {} ESCAPE '\\'")
			args = append(args, "%"+wildcardReplacer.Replace(ext))
		}
		b.WriteString(")")
		extFilter = sq.Expr(b.String(), args...)
	}
	cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
			" AND {extFilter}",
		Values: []any{
			sq.StringParam("pattern", wildcardReplacer.Replace(path.Join(siteGen.sitePrefix, "output"))+"/%"),
			sq.Param("extFilter", extFilter),
		},
	}, func(row *sq.Row) (result struct {
		FileID   ID
		FilePath string
	}) {
		result.FileID = row.UUID("file_id")
		result.FilePath = row.String("file_path")
		return result
	})
	if err != nil {
		return nil, stacktrace.New(err)
	}
	defer cursor.Close()
	siteGen.imgFileIDs = make(map[string]ID)
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return nil, stacktrace.New(err)
		}
		siteGen.imgFileIDs[result.FilePath] = result.FileID
	}
	err = cursor.Close()
	if err != nil {
		return nil, stacktrace.New(err)
	}
	return siteGen, nil
}

// ParseTemplate parses text as a template body for name. Template references
// starting with "/themes/" and ending in ".html" will be looked for in the
// site's themes folder.
func (siteGen *SiteGenerator) ParseTemplate(ctx context.Context, name, text string) (*template.Template, error) {
	return siteGen.parseTemplate(ctx, name, text, nil)
}

// parseTemplate is the auxiliary recursive function that ParseTemplate calls.
// The callers argument is used to keep track of the templates responsible for
// calling parseTemplate each time, so that we can detect if we are in a loop.
func (siteGen *SiteGenerator) parseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
	currentTemplate, err := template.New(name).Funcs(siteGen.funcMap).Parse(text)
	if err != nil {
		return nil, NewTemplateError(err)
	}
	internalTemplates := currentTemplate.Templates()
	slices.SortFunc(internalTemplates, func(a, b *template.Template) int {
		return strings.Compare(a.Name(), b.Name())
	})
	for _, tmpl := range internalTemplates {
		internalName := tmpl.Name()
		if strings.HasSuffix(internalName, ".html") && internalName != name {
			return nil, TemplateError{
				Name:         name,
				ErrorMessage: "define " + strconv.Quote(internalName) + ": internal template name cannot end with .html",
			}
		}
	}
	// Get the list of external templates referenced by the current template.
	var externalNames []string
	var node parse.Node
	var nodes []parse.Node
	for _, tmpl := range internalTemplates {
		if tmpl.Tree == nil || tmpl.Tree.Root == nil {
			continue
		}
		nodes = append(nodes, tmpl.Tree.Root.Nodes...)
		for len(nodes) > 0 {
			node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
			switch node := node.(type) {
			case *parse.ListNode:
				if node == nil {
					continue
				}
				nodes = append(nodes, node.Nodes...)
			case *parse.BranchNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.RangeNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.TemplateNode:
				if strings.HasSuffix(node.Name, ".html") {
					if !strings.HasPrefix(node.Name, "/themes/") {
						return nil, TemplateError{
							Name:         name,
							ErrorMessage: "template " + strconv.Quote(node.Name) + ": external template name must start with /themes/",
						}
					}
					externalNames = append(externalNames, node.Name)
				}
			}
		}
	}
	// Sort the list of external template names so that looping through them
	// becomes deterministic.
	slices.Sort(externalNames)
	externalNames = slices.Compact(externalNames)
	group, groupctx := errgroup.WithContext(ctx)
	externalTemplates := make([]*template.Template, len(externalNames))
	for i, externalName := range externalNames {
		i, externalName := i, externalName
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			n := slices.Index(callers, externalName)
			if n >= 0 {
				return TemplateError{
					Name:         externalName,
					ErrorMessage: "circular template reference: " + strings.Join(callers[n:], "=>") + " => " + externalName,
				}
			}
			// If a template is currently being parsed, wait for it to finish
			// before checking the templateCache for the result.
			siteGen.mutex.Lock()
			wait := siteGen.templateInProgress[externalName]
			siteGen.mutex.Unlock()
			if wait != nil {
				select {
				case <-groupctx.Done():
					return err
				case <-wait:
					break
				}
			}
			siteGen.mutex.Lock()
			cachedTemplate, ok := siteGen.templateCache[externalName]
			siteGen.mutex.Unlock()
			if ok {
				// We found the template; add it to the slice and exit. Note
				// that the cachedTemplate may be nil, if parsing that template
				// had resulted in errors.
				externalTemplates[i] = cachedTemplate
				return nil
			}
			// We put a nil pointer into the templateCache first. This is to
			// indicate that we have already seen this template. If parsing
			// succeeds, we simply overwrite the nil entry with the parsed
			// template. If we fail, the cachedTemplate pointer stays nil and
			// should be treated as a signal by other goroutines that parsing
			// this template has errors. Other goroutines are blocked from
			// accessing the cachedTemplate pointer until the wait channel is
			// closed by the defer function below (which is once this goroutine
			// exits).
			wait = make(chan struct{})
			siteGen.mutex.Lock()
			siteGen.templateCache[externalName] = nil
			siteGen.templateInProgress[externalName] = wait
			siteGen.mutex.Unlock()
			defer func() {
				siteGen.mutex.Lock()
				siteGen.templateCache[externalName] = cachedTemplate
				delete(siteGen.templateInProgress, externalName)
				close(wait)
				siteGen.mutex.Unlock()
			}()
			file, err := siteGen.fsys.WithContext(groupctx).Open(path.Join(siteGen.sitePrefix, "output", externalName))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return TemplateError{
						Name:         name,
						ErrorMessage: "template " + strconv.Quote(externalName) + " does not exist",
					}
				}
				return stacktrace.New(err)
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return stacktrace.New(err)
			}
			if fileInfo.IsDir() {
				return TemplateError{
					Name:         name,
					ErrorMessage: strconv.Quote(externalName) + " is a folder",
				}
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return stacktrace.New(err)
			}
			err = file.Close()
			if err != nil {
				return stacktrace.New(err)
			}
			newCallers := append(append(make([]string, 0, len(callers)+1), callers...), externalName)
			externalTemplate, err := siteGen.parseTemplate(groupctx, externalName, b.String(), newCallers)
			if err != nil {
				return err
			}
			// Important! Before we execute any template, it must be cloned.
			// This is because once a template has been executed it is no
			// longer pristine i.e. it cannot be added to another template
			// using AddParseTree (html/template has this restriction in order
			// for its contextually auto-escaped HTML feature to work).
			externalTemplates[i], err = externalTemplate.Clone()
			if err != nil {
				return stacktrace.New(err)
			}
			cachedTemplate = externalTemplate
			return nil
		})
	}
	err = group.Wait()
	if err != nil {
		return nil, err
	}
	finalTemplate := template.New(name).Funcs(siteGen.funcMap)
	for i, externalTemplate := range externalTemplates {
		for _, tmpl := range externalTemplate.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, TemplateError{
					Name:         name,
					ErrorMessage: fmt.Sprintf("%s: add %s: %s", externalNames[i], tmpl.Name(), err),
				}
			}
		}
	}
	for _, tmpl := range internalTemplates {
		_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
		if err != nil {
			return nil, TemplateError{
				Name:         name,
				ErrorMessage: fmt.Sprintf("add %s: %s", tmpl.Name(), err),
			}
		}
	}
	return finalTemplate.Lookup(name), nil
}

// PageData is the data used to render a page.
type PageData struct {
	// Site information.
	Site Site

	// Parent URL of the page.
	Parent string

	// Name of the page.
	Name string

	// Title of the page.
	Title string

	// ChildPages of the page.
	ChildPages []Page

	// ContentMap of markdown file names to their file contents. Convert it to
	// HTML using the markdownToHTML template function.
	ContentMap map[string]string

	// Images belonging to the page.
	Images []Image

	// ModificationTime of the page.
	ModificationTime time.Time

	// CreationTime of the page.
	CreationTime time.Time
}

// Page contains metadata about a page.
type Page struct {
	// Parent URL of the page.
	Parent string

	// Name of the page.
	Name string

	// Title of the page.
	Title string
}

// Image contains metadata about an image.
type Image struct {
	// Parent URL of the image.
	Parent string

	// Name of the image.
	Name string

	// AltText of the image.
	AltText string

	// Caption of the image.
	Caption string
}

var (
	titleConverter       = transform.NewTitleConverter(transform.APStyle)
	urlSeparatorReplacer = strings.NewReplacer("-", " ", "_", " ")
)

// GeneratePage generates a page. filePath is the file path to the source .html
// page in the pages/ directory, text is the source text of the page, modTime
// and creationTime are when the page was modified and created.
func (siteGen *SiteGenerator) GeneratePage(ctx context.Context, filePath, text string, modTime, creationTime time.Time) error {
	// urlPath is the URL of the resultant page.
	urlPath := strings.TrimPrefix(filePath, "pages/")
	if urlPath == "index.html" {
		urlPath = ""
	} else {
		urlPath = strings.TrimSuffix(urlPath, path.Ext(urlPath))
	}
	// Sanity check: /posts/ and /themes/ are reserved for user posts and user
	// themes, we absolutely do not want to generate any page here or else it
	// might overwrite existing user posts and themes.
	if urlPath == "posts" || urlPath == "themes" {
		return stacktrace.New(fmt.Errorf("attempted to generate page in %s", path.Join(siteGen.sitePrefix, "output", urlPath)))
	}
	// outputDir is where we will render the page output to.
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	pageData := PageData{
		Site:             siteGen.Site,
		Parent:           path.Dir(urlPath),
		Name:             path.Base(urlPath),
		ChildPages:       []Page{},
		ContentMap:       make(map[string]string),
		Images:           []Image{},
		ModificationTime: modTime.UTC(),
		CreationTime:     creationTime.UTC(),
	}
	if pageData.Parent == "." {
		pageData.Parent = ""
	}
	if pageData.Name == "." {
		pageData.Name = ""
	}
	line, _, _ := strings.Cut(text, "\n")
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "<!--") && strings.HasSuffix(line, "-->") {
		line := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<!--"), "-->"))
		if strings.HasPrefix(line, "#title ") {
			pageData.Title = strings.TrimSpace(strings.TrimPrefix(line, "#title "))
		}
	} else if strings.HasPrefix(line, "<title>") && strings.HasSuffix(line, "</title>") {
		pageData.Title = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<title>"), "</title>"))
	}
	if pageData.Title == "" {
		pageData.Title = titleConverter.Title(urlSeparatorReplacer.Replace(pageData.Name))
	}
	var err error
	var tmpl *template.Template
	group, groupctx := errgroup.WithContext(ctx)
	// Parse the page template.
	group.Go(func() (err error) {
		defer stacktrace.RecoverPanic(&err)
		tmpl, err = siteGen.ParseTemplate(groupctx, "/"+filePath, text)
		if err != nil {
			return err
		}
		return nil
	})
	// Fetch all the images and markdown files that belong to the page.
	group.Go(func() (err error) {
		defer stacktrace.RecoverPanic(&err)
		markdownMu := sync.Mutex{}
		databaseFS, isDatabaseFS := &DatabaseFS{}, false
		switch v := siteGen.fsys.(type) {
		case interface{ As(any) bool }:
			isDatabaseFS = v.As(&databaseFS)
		}
		if isDatabaseFS {
			var b strings.Builder
			args := make([]any, 0, len(imgExts)+1)
			b.WriteString("(file_path LIKE '%.md' ESCAPE '\\'")
			for _, ext := range imgExts {
				b.WriteString(" OR file_path LIKE {} ESCAPE '\\'")
				args = append(args, "%"+wildcardReplacer.Replace(ext))
			}
			b.WriteString(")")
			extFilter := sq.Expr(b.String(), args...)
			cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
					" AND NOT is_dir" +
					" AND {extFilter}" +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("outputDir", outputDir),
					sq.Param("extFilter", extFilter),
				},
			}, func(row *sq.Row) (result struct {
				FilePath string
				Text     []byte
			}) {
				result.FilePath = row.String("file_path")
				result.Text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
				return result
			})
			if err != nil {
				return stacktrace.New(err)
			}
			defer cursor.Close()
			subgroup, subctx := errgroup.WithContext(groupctx)
			for cursor.Next() {
				result, err := cursor.Result()
				if err != nil {
					return stacktrace.New(err)
				}
				name := path.Base(result.FilePath)
				fileType := AllowedFileTypes[path.Ext(result.FilePath)]
				if fileType.Has(AttributeImg) {
					pageData.Images = append(pageData.Images, Image{
						Parent: urlPath,
						Name:   name,
					})
					i := len(pageData.Images) - 1
					subgroup.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						defer func() {
							result.Text = result.Text[:0]
							bufPool.Put(bytes.NewBuffer(result.Text))
						}()
						err = subctx.Err()
						if err != nil {
							return stacktrace.New(err)
						}
						var altText []byte
						result.Text = bytes.TrimSpace(result.Text)
						if bytes.HasPrefix(result.Text, []byte("!alt ")) {
							altText, result.Text, _ = bytes.Cut(result.Text, []byte("\n"))
							altText = bytes.TrimSpace(bytes.TrimPrefix(altText, []byte("!alt ")))
							result.Text = bytes.TrimSpace(result.Text)
						}
						pageData.Images[i].AltText = string(altText)
						pageData.Images[i].Caption = string(result.Text)
						return nil
					})
				} else {
					subgroup.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						defer func() {
							result.Text = result.Text[:0]
							bufPool.Put(bytes.NewBuffer(result.Text))
						}()
						err = subctx.Err()
						if err != nil {
							return stacktrace.New(err)
						}
						markdownMu.Lock()
						pageData.ContentMap[name] = string(result.Text)
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = cursor.Close()
			if err != nil {
				return stacktrace.New(err)
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(groupctx).ReadDir(outputDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			subgroup, subctx := errgroup.WithContext(groupctx)
			for _, dirEntry := range dirEntries {
				dirEntry := dirEntry
				name := dirEntry.Name()
				fileType := AllowedFileTypes[path.Ext(name)]
				if fileType.Has(AttributeImg) {
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				} else if fileType.Ext == ".md" {
					subgroup.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						file, err := siteGen.fsys.WithContext(subctx).Open(path.Join(outputDir, name))
						if err != nil {
							return stacktrace.New(err)
						}
						defer file.Close()
						buf := bufPool.Get().(*bytes.Buffer)
						defer func() {
							if buf.Cap() <= maxPoolableBufferCapacity {
								buf.Reset()
								bufPool.Put(buf)
							}
						}()
						_, err = buf.ReadFrom(file)
						if err != nil {
							return stacktrace.New(err)
						}
						markdownMu.Lock()
						pageData.ContentMap[name] = buf.String()
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
		}
		return nil
	})
	// Fetch the child pages of the page.
	group.Go(func() (err error) {
		defer stacktrace.RecoverPanic(&err)
		pageDir := path.Join(siteGen.sitePrefix, "pages", urlPath)
		databaseFS, isDatabaseFS := &DatabaseFS{}, false
		switch v := siteGen.fsys.(type) {
		case interface{ As(any) bool }:
			isDatabaseFS = v.As(&databaseFS)
		}
		if isDatabaseFS {
			pageData.ChildPages, err = sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {pageDir})" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html' ESCAPE '\\'" +
					" AND file_path NOT IN ({indexPage}, {notFoundPage})" +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("pageDir", pageDir),
					sq.StringParam("indexPage", path.Join(pageDir, "index.html")),
					sq.StringParam("notFoundPage", path.Join(pageDir, "404.html")),
				},
			}, func(row *sq.Row) Page {
				page := Page{
					Parent: urlPath,
					Name:   strings.TrimSuffix(path.Base(row.String("file_path")), ".html"),
				}
				line := strings.TrimSpace(row.String("{}", sq.DialectExpression{
					Default: sq.Expr("substr(text, 1, instr(text, char(10))-1)"),
					Cases: []sq.DialectCase{{
						Dialect: "postgres",
						Result:  sq.Expr("split_part(text, chr(10), 1)"),
					}, {
						Dialect: "mysql",
						Result:  sq.Expr("substring_index(text, char(10), 1)"),
					}},
				}))
				if strings.HasPrefix(line, "<!--") && strings.HasSuffix(line, "-->") {
					line := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<!--"), "-->"))
					if strings.HasPrefix(line, "#title ") {
						page.Title = strings.TrimSpace(strings.TrimPrefix(line, "#title "))
					}
				} else if strings.HasPrefix(line, "<title>") && strings.HasSuffix(line, "</title>") {
					page.Title = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<title>"), "</title>"))
				}
				if page.Title == "" {
					page.Title = titleConverter.Title(urlSeparatorReplacer.Replace(page.Name))
				}
				return page
			})
			if err != nil {
				return stacktrace.New(err)
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(groupctx).ReadDir(pageDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			pageData.ChildPages = make([]Page, len(dirEntries))
			subgroup, subctx := errgroup.WithContext(groupctx)
			for i, dirEntry := range dirEntries {
				i, dirEntry := i, dirEntry
				subgroup.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					name := dirEntry.Name()
					if dirEntry.IsDir() || !strings.HasSuffix(name, ".html") {
						return nil
					}
					if urlPath == "" {
						if name == "index.html" || name == "404.html" {
							return nil
						}
					}
					pageData.ChildPages[i].Parent = urlPath
					pageData.ChildPages[i].Name = strings.TrimSuffix(name, ".html")
					file, err := siteGen.fsys.WithContext(subctx).Open(path.Join(pageDir, name))
					if err != nil {
						return stacktrace.New(err)
					}
					defer file.Close()
					reader := readerPool.Get().(*bufio.Reader)
					reader.Reset(file)
					defer func() {
						reader.Reset(bytes.NewReader(nil))
						readerPool.Put(reader)
					}()
					done := false
					for !done {
						line, err := reader.ReadSlice('\n')
						if err != nil {
							if err != io.EOF {
								return stacktrace.New(err)
							}
							done = true
						}
						line = bytes.TrimSpace(line)
						if bytes.HasPrefix(line, []byte("<!--")) && bytes.HasSuffix(line, []byte("-->")) {
							line := bytes.TrimSpace(bytes.TrimSuffix(bytes.TrimPrefix(line, []byte("<!--")), []byte("-->")))
							if bytes.HasPrefix(line, []byte("#title ")) {
								pageData.ChildPages[i].Title = string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("#title "))))
							}
						} else if bytes.HasPrefix(line, []byte("<title>")) && bytes.HasSuffix(line, []byte("</title>")) {
							pageData.ChildPages[i].Title = string(bytes.TrimSpace(bytes.TrimSuffix(bytes.TrimPrefix(line, []byte("<title>")), []byte("</title>"))))
						}
						break
					}
					if pageData.ChildPages[i].Title == "" {
						pageData.ChildPages[i].Title = titleConverter.Title(urlSeparatorReplacer.Replace(pageData.ChildPages[i].Name))
					}
					return nil
				})
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			n := 0
			for _, childPage := range pageData.ChildPages {
				if childPage != (Page{}) {
					pageData.ChildPages[n] = childPage
					n++
				}
			}
			pageData.ChildPages = pageData.ChildPages[:n]
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		return err
	}
	if pageData.ChildPages == nil {
		pageData.ChildPages = []Page{}
	}
	// Prepare the writer.
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
		err := siteGen.fsys.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return stacktrace.New(err)
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	defer writer.Close()
	// Write the necessary HTML boilerplate for every page.
	_, err = io.Copy(writer, strings.NewReader("<!DOCTYPE html>\n"+
		"<html lang='"+template.HTMLEscapeString(siteGen.Site.LanguageCode)+"'>\n"+
		"<meta charset='utf-8'>\n"+
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
		"<link rel='icon' href='"+template.HTMLEscapeString(string(siteGen.Site.Favicon))+"'>\n",
	))
	if err != nil {
		return stacktrace.New(err)
	}
	var isDatabaseFS bool
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&DatabaseFS{})
	}
	// Execute the page template into the writer.
	if siteGen.cdnDomain != "" && isDatabaseFS {
		pipeReader, pipeWriter := io.Pipe()
		result := make(chan error, 1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					result <- stacktrace.New(fmt.Errorf("panic: %v", v))
				}
			}()
			result <- siteGen.rewriteURLs(writer, pipeReader, urlPath)
		}()
		err = tmpl.Execute(pipeWriter, pageData)
		if err != nil {
			templateErr := NewTemplateError(err)
			io.Copy(pipeWriter, strings.NewReader(html.EscapeString(templateErr.Error())))
			return templateErr
		}
		pipeWriter.Close()
		err = <-result
		if err != nil {
			return err
		}
	} else {
		err = tmpl.Execute(writer, pageData)
		if err != nil {
			templateErr := NewTemplateError(err)
			io.Copy(writer, strings.NewReader(html.EscapeString(templateErr.Error())))
			return templateErr
		}
	}
	err = writer.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

// PostData is the data used to render a post.
type PostData struct {
	// Site information.
	Site Site

	// Category of the post.
	Category string

	// Name of the post.
	Name string

	// Title of the post.
	Title string

	// Content of the post.
	Content string

	// Images belonging to the post that are not already explicitly included in
	// the post content.
	Images []Image

	// CreationTime of the post.
	CreationTime time.Time

	// ModificationTime of the post.
	ModificationTime time.Time
}

// GeneratePost generates a post. filePath is the file path to the source post
// in the posts/ directory and text is the text of the source post.
func (siteGen *SiteGenerator) GeneratePost(ctx context.Context, filePath, text string, modTime, creationTime time.Time, tmpl *template.Template) error {
	timestampPrefix, _, _ := strings.Cut(path.Base(filePath), "-")
	if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
		b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
		if len(b) == 5 && err == nil {
			var timestamp [8]byte
			copy(timestamp[len(timestamp)-5:], b)
			creationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0).UTC()
		}
	}
	urlPath := strings.TrimSuffix(filePath, path.Ext(filePath))
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	postData := PostData{
		Site:             siteGen.Site,
		Category:         path.Dir(strings.TrimPrefix(urlPath, "posts/")),
		Name:             path.Base(strings.TrimPrefix(urlPath, "posts/")),
		Images:           []Image{},
		CreationTime:     creationTime.UTC(),
		ModificationTime: modTime.UTC(),
	}
	if strings.Contains(postData.Category, "/") {
		return stacktrace.New(fmt.Errorf("invalid post category"))
	}
	if postData.Category == "." {
		postData.Category = ""
	}
	// Title
	var line string
	remainder := text
	for len(remainder) > 0 {
		line, remainder, _ = strings.Cut(remainder, "\n")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		postData.Title = markdownTextOnly(siteGen.markdown.Parser(), []byte(line))
		if postData.Title == "" {
			continue
		}
		break
	}
	if postData.Title == "" {
		postData.Title = postData.Name
	}
	// Content
	postData.Content = text
	imgIsMentioned := make(map[string]struct{})
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufPool.Put(buf)
	}()
	err := siteGen.markdown.Convert([]byte(text), buf)
	if err != nil {
		return stacktrace.New(err)
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(buf.Bytes()))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			err := tokenizer.Err()
			if err == io.EOF {
				break
			}
			return stacktrace.New(err)
		}
		if tokenType == html.SelfClosingTagToken || tokenType == html.StartTagToken {
			var key, val []byte
			name, moreAttr := tokenizer.TagName()
			if !bytes.Equal(name, []byte("img")) {
				continue
			}
			for moreAttr {
				key, val, moreAttr = tokenizer.TagAttr()
				if !bytes.Equal(key, []byte("src")) {
					continue
				}
				uri, err := url.Parse(string(val))
				if err != nil {
					continue
				}
				if uri.Scheme != "" || uri.Host != "" || strings.Contains(uri.Path, "/") {
					continue
				}
				imgIsMentioned[uri.Path] = struct{}{}
			}
		}
	}
	// Images.
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	if isDatabaseFS {
		extFilter := sq.Expr("1 = 1")
		if len(imgExts) > 0 {
			var b strings.Builder
			args := make([]any, 0, len(imgExts))
			b.WriteString("(")
			for i, ext := range imgExts {
				if i > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString("file_path LIKE {} ESCAPE '\\'")
				args = append(args, "%"+wildcardReplacer.Replace(ext))
			}
			b.WriteString(")")
			extFilter = sq.Expr(b.String(), args...)
		}
		cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
				" AND NOT is_dir" +
				" AND {extFilter} " +
				" ORDER BY file_path",
			Values: []any{
				sq.StringParam("outputDir", outputDir),
				sq.Param("extFilter", extFilter),
			},
		}, func(row *sq.Row) (result struct {
			FilePath string
			Text     []byte
		}) {
			result.FilePath = row.String("file_path")
			result.Text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
			return result
		})
		if err != nil {
			return stacktrace.New(err)
		}
		defer cursor.Close()
		group, groupctx := errgroup.WithContext(ctx)
		for cursor.Next() {
			result, err := cursor.Result()
			if err != nil {
				return stacktrace.New(err)
			}
			name := path.Base(result.FilePath)
			if _, ok := imgIsMentioned[name]; ok {
				continue
			}
			postData.Images = append(postData.Images, Image{
				Parent: urlPath,
				Name:   name,
			})
			i := len(postData.Images) - 1
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				defer func() {
					if len(result.Text) <= maxPoolableBufferCapacity {
						result.Text = result.Text[:0]
						bufPool.Put(bytes.NewBuffer(result.Text))
					}
				}()
				err = groupctx.Err()
				if err != nil {
					return stacktrace.New(err)
				}
				var altText []byte
				result.Text = bytes.TrimSpace(result.Text)
				if bytes.HasPrefix(result.Text, []byte("!alt ")) {
					altText, result.Text, _ = bytes.Cut(result.Text, []byte("\n"))
					altText = bytes.TrimSpace(bytes.TrimPrefix(altText, []byte("!alt ")))
					result.Text = bytes.TrimSpace(result.Text)
				}
				postData.Images[i].AltText = string(altText)
				postData.Images[i].Caption = string(result.Text)
				return nil
			})
		}
		err = cursor.Close()
		if err != nil {
			return stacktrace.New(err)
		}
		err = group.Wait()
		if err != nil {
			return err
		}
	} else {
		dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(outputDir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, dirEntry := range dirEntries {
			name := dirEntry.Name()
			if dirEntry.IsDir() {
				continue
			}
			fileType := AllowedFileTypes[path.Ext(name)]
			if fileType.Has(AttributeImg) {
				if _, ok := imgIsMentioned[name]; ok {
					continue
				}
				postData.Images = append(postData.Images, Image{Parent: urlPath, Name: name})
			}
		}
	}
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
		err := siteGen.fsys.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return stacktrace.New(err)
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	defer writer.Close()
	_, err = io.Copy(writer, strings.NewReader("<!DOCTYPE html>\n"+
		"<html lang='"+template.HTMLEscapeString(siteGen.Site.LanguageCode)+"'>\n"+
		"<meta charset='utf-8'>\n"+
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
		"<link rel='icon' href='"+template.HTMLEscapeString(string(siteGen.Site.Favicon))+"'>\n",
	))
	if err != nil {
		return stacktrace.New(err)
	}
	if siteGen.cdnDomain != "" && isDatabaseFS {
		pipeReader, pipeWriter := io.Pipe()
		result := make(chan error, 1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					result <- stacktrace.New(fmt.Errorf("panic: %v", v))
				}
			}()
			result <- siteGen.rewriteURLs(writer, pipeReader, urlPath)
		}()
		err = tmpl.Execute(pipeWriter, postData)
		if err != nil {
			templateErr := NewTemplateError(err)
			io.Copy(pipeWriter, strings.NewReader(html.EscapeString(templateErr.Error())))
			return templateErr
		}
		pipeWriter.Close()
		err = <-result
		if err != nil {
			return err
		}
	} else {
		err = tmpl.Execute(writer, postData)
		if err != nil {
			templateErr := NewTemplateError(err)
			io.Copy(writer, strings.NewReader(html.EscapeString(templateErr.Error())))
			return templateErr
		}
	}
	err = writer.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

// GeneratePosts generates all posts for a given category.
func (siteGen *SiteGenerator) GeneratePosts(ctx context.Context, category string, tmpl *template.Template) (int64, error) {
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	if isDatabaseFS {
		type File struct {
			FilePath     string
			Text         string
			ModTime      time.Time
			CreationTime time.Time
		}
		cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md' ESCAPE '\\'",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) File {
			return File{
				FilePath:     row.String("file_path"),
				Text:         row.String("text"),
				ModTime:      row.Time("mod_time"),
				CreationTime: row.Time("creation_time"),
			}
		})
		if err != nil {
			return 0, stacktrace.New(err)
		}
		defer cursor.Close()
		var count atomic.Int64
		group, groupctx := errgroup.WithContext(ctx)
		for cursor.Next() {
			file, err := cursor.Result()
			if err != nil {
				return 0, stacktrace.New(err)
			}
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				if siteGen.sitePrefix != "" {
					_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
				}
				err = siteGen.GeneratePost(groupctx, file.FilePath, file.Text, file.ModTime, file.CreationTime, tmpl)
				if err != nil {
					return err
				}
				count.Add(1)
				return nil
			})
		}
		err = cursor.Close()
		if err != nil {
			return 0, stacktrace.New(err)
		}
		err = group.Wait()
		if err != nil {
			return count.Load(), err
		}
		return count.Load(), nil
	}
	dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(path.Join(siteGen.sitePrefix, "posts", category))
	if err != nil {
		return 0, stacktrace.New(err)
	}
	var count atomic.Int64
	group, groupctx := errgroup.WithContext(ctx)
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		name := dirEntry.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			file, err := siteGen.fsys.WithContext(groupctx).Open(path.Join(siteGen.sitePrefix, "posts", category, name))
			if err != nil {
				return stacktrace.New(err)
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return stacktrace.New(err)
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return stacktrace.New(err)
			}
			var absolutePath string
			switch v := siteGen.fsys.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, siteGen.sitePrefix, "posts", category, name)
				}
			}
			creationTime := CreationTime(absolutePath, fileInfo)
			err = siteGen.GeneratePost(groupctx, path.Join("posts", category, name), b.String(), fileInfo.ModTime(), creationTime, tmpl)
			if err != nil {
				return err
			}
			count.Add(1)
			return nil
		})
	}
	err = group.Wait()
	if err != nil {
		return count.Load(), err
	}
	return count.Load(), nil
}

// Post contains metadata about a post.
type Post struct {
	// Category of the post.
	Category string

	// Name of the post.
	Name string

	// Title of the post.
	Title string

	// Preview of the post.
	Preview string

	// Whether the post has more text after the preview.
	HasMore bool

	// Content of the post.
	Content string

	// Images belonging to the post.
	Images []Image

	// CreationTime of the post.
	CreationTime time.Time

	// ModificationTime of the post.
	ModificationTime time.Time

	// text of the post. nil slice means no value, empty slice means empty
	// value.
	text []byte
}

// PostListData is the data used to render a post list page.
type PostListData struct {
	// Site information.
	Site Site

	// Category of the post list.
	Category string

	// Pagination information for the post list.
	Pagination Pagination

	// The lists of posts for the current page of the post list.
	Posts []Post
}

// GeneratePostList generates the post list for a category, which contain one
// or more post list pages.
func (siteGen *SiteGenerator) GeneratePostList(ctx context.Context, category string, tmpl *template.Template) (int64, error) {
	var config struct {
		PostsPerPage int
	}
	if strings.Contains(category, "/") {
		return 0, fmt.Errorf("invalid post category")
	}
	b, err := fs.ReadFile(siteGen.fsys.WithContext(ctx), path.Join(siteGen.sitePrefix, "posts", category, "postlist.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, stacktrace.New(err)
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &config)
		if err != nil {
			return 0, stacktrace.New(err)
		}
	}
	if config.PostsPerPage <= 0 {
		config.PostsPerPage = 100
	}
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	page := 1
	if isDatabaseFS {
		count, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md' ESCAPE '\\'",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) int {
			return row.Int("COUNT(*)")
		})
		if err != nil {
			return 0, stacktrace.New(err)
		}
		lastPage := int(math.Ceil(float64(count) / float64(config.PostsPerPage)))
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			filePaths, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("parent", path.Join(siteGen.sitePrefix, "output/posts", category)),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				return stacktrace.New(err)
			}
			subgroup, subctx := errgroup.WithContext(groupctx)
			for _, filePath := range filePaths {
				filePath := filePath
				n, err := strconv.ParseInt(path.Base(filePath), 10, 64)
				if err != nil {
					continue
				}
				if int(n) <= lastPage {
					continue
				}
				subgroup.Go(func() (err error) {
					stacktrace.RecoverPanic(&err)
					err = databaseFS.WithContext(subctx).RemoveAll(filePath)
					if err != nil {
						return stacktrace.New(err)
					}
					return nil
				})
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md' ESCAPE '\\'" +
				" ORDER BY file_path DESC",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) Post {
			var post Post
			post.Category = category
			name := path.Base(row.String("file_path"))
			post.Name = strings.TrimSuffix(name, path.Ext(name))
			post.CreationTime = row.Time("creation_time")
			post.ModificationTime = row.Time("mod_time")
			post.text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
			return post
		})
		if err != nil {
			return 0, stacktrace.New(err)
		}
		defer cursor.Close()
		page := 1
		batch := make([]Post, 0, config.PostsPerPage)
		for cursor.Next() {
			post, err := cursor.Result()
			if err != nil {
				return int64(page), stacktrace.New(err)
			}
			timestampPrefix, _, _ := strings.Cut(post.Name, "-")
			if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
				b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
				if len(b) == 5 && err == nil {
					var timestamp [8]byte
					copy(timestamp[len(timestamp)-5:], b)
					post.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0).UTC()
				}
			}
			batch = append(batch, post)
			if len(batch) >= config.PostsPerPage {
				currentPage := page
				page++
				posts := slices.Clone(batch)
				batch = batch[:0]
				group.Go(func() (err error) {
					stacktrace.RecoverPanic(&err)
					return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, currentPage, posts)
				})
			}
		}
		err = cursor.Close()
		if err != nil {
			return int64(page), stacktrace.New(err)
		}
		if len(batch) > 0 {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, page, batch)
			})
		}
		err = group.Wait()
		if err != nil {
			return int64(page), err
		}
		if page == 1 && len(batch) == 0 {
			err := siteGen.GeneratePostListPage(ctx, category, tmpl, 1, 1, nil)
			if err != nil {
				return int64(page), err
			}
		}
	} else {
		dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(path.Join(siteGen.sitePrefix, "posts", category))
		if err != nil {
			return 0, stacktrace.New(err)
		}
		n := 0
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				continue
			}
			if !strings.HasSuffix(dirEntry.Name(), ".md") {
				continue
			}
			dirEntries[n] = dirEntry
			n++
		}
		dirEntries = dirEntries[:n]
		slices.Reverse(dirEntries)
		lastPage := int(math.Ceil(float64(len(dirEntries)) / float64(config.PostsPerPage)))
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			dirEntries, err := siteGen.fsys.WithContext(groupctx).ReadDir(path.Join(siteGen.sitePrefix, "output/posts", category))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return stacktrace.New(err)
			}
			subgroup, subctx := errgroup.WithContext(groupctx)
			for _, dirEntry := range dirEntries {
				dirEntry := dirEntry
				if !dirEntry.IsDir() {
					continue
				}
				n, err := strconv.ParseInt(dirEntry.Name(), 10, 64)
				if err != nil {
					continue
				}
				if int(n) <= lastPage {
					continue
				}
				subgroup.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					err = siteGen.fsys.WithContext(subctx).RemoveAll(path.Join(siteGen.sitePrefix, "output/posts", category, strconv.FormatInt(n, 10)))
					if err != nil {
						return stacktrace.New(err)
					}
					return nil
				})
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		batch := make([]Post, 0, config.PostsPerPage)
		var absoluteDir string
		switch v := siteGen.fsys.(type) {
		case interface{ As(any) bool }:
			var directoryFS *DirectoryFS
			if v.As(&directoryFS) {
				absoluteDir = path.Join(directoryFS.RootDir, siteGen.sitePrefix, "posts", category)
			}
		}
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				return int64(page), stacktrace.New(err)
			}
			name := fileInfo.Name()
			creationTime := CreationTime(path.Join(absoluteDir, name), fileInfo)
			timestampPrefix, _, _ := strings.Cut(name, "-")
			if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
				b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
				if len(b) == 5 && err == nil {
					var timestamp [8]byte
					copy(timestamp[len(timestamp)-5:], b)
					creationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0).UTC()
				}
			}
			batch = append(batch, Post{
				Category:         category,
				Name:             strings.TrimSuffix(name, path.Ext(name)),
				CreationTime:     creationTime,
				ModificationTime: fileInfo.ModTime(),
			})
			if len(batch) >= config.PostsPerPage {
				currentPage := page
				page++
				posts := slices.Clone(batch)
				batch = batch[:0]
				group.Go(func() (err error) {
					defer stacktrace.RecoverPanic(&err)
					return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, currentPage, posts)
				})
			}
		}
		if len(batch) > 0 {
			group.Go(func() (err error) {
				defer stacktrace.RecoverPanic(&err)
				return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, page, batch)
			})
		}
		err = group.Wait()
		if err != nil {
			return int64(page), err
		}
		if page == 1 && len(batch) == 0 {
			err := siteGen.GeneratePostListPage(ctx, category, tmpl, 1, 1, []Post{})
			if err != nil {
				return int64(page), err
			}
		}
	}
	return int64(page), nil
}

// GeneratePostListPage generates a singular page of the post list for a
// category.
func (siteGen *SiteGenerator) GeneratePostListPage(ctx context.Context, category string, tmpl *template.Template, lastPage, currentPage int, posts []Post) error {
	groupA, groupctxA := errgroup.WithContext(ctx)
	for i := range posts {
		i := i
		groupA.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			if posts[i].text != nil {
				defer func() {
					if len(posts[i].text) <= maxPoolableBufferCapacity {
						posts[i].text = posts[i].text[:0]
						bufPool.Put(bytes.NewBuffer(posts[i].text))
						posts[i].text = nil
					}
				}()
			} else {
				file, err := siteGen.fsys.WithContext(groupctxA).Open(path.Join(siteGen.sitePrefix, "posts", category, posts[i].Name+".md"))
				if err != nil {
					return stacktrace.New(err)
				}
				defer file.Close()
				buf := bufPool.Get().(*bytes.Buffer)
				defer func() {
					if buf.Cap() <= maxPoolableBufferCapacity {
						buf.Reset()
						bufPool.Put(buf)
						posts[i].text = nil
					}
				}()
				_, err = buf.ReadFrom(file)
				if err != nil {
					return stacktrace.New(err)
				}
				posts[i].text = buf.Bytes()
			}
			var line []byte
			remainder := posts[i].text
			for len(remainder) > 0 {
				line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if posts[i].Title == "" {
					posts[i].Title = markdownTextOnly(siteGen.markdown.Parser(), line)
					continue
				}
				if posts[i].Preview == "" {
					posts[i].Preview = markdownTextOnly(siteGen.markdown.Parser(), line)
					posts[i].HasMore = len(bytes.TrimSpace(remainder)) > 0
					continue
				}
				break
			}
			if posts[i].Title == "" {
				posts[i].Title = posts[i].Name
			}
			posts[i].Content = string(posts[i].text)
			return nil
		})
		groupA.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			outputDir := path.Join(siteGen.sitePrefix, "output/posts", posts[i].Category, posts[i].Name)
			databaseFS, isDatabaseFS := &DatabaseFS{}, false
			switch v := siteGen.fsys.(type) {
			case interface{ As(any) bool }:
				isDatabaseFS = v.As(&databaseFS)
			}
			if isDatabaseFS {
				extFilter := sq.Expr("1 = 1")
				if len(imgExts) > 0 {
					var b strings.Builder
					args := make([]any, 0, len(imgExts))
					b.WriteString("(")
					for i, ext := range imgExts {
						if i > 0 {
							b.WriteString(" OR ")
						}
						b.WriteString("file_path LIKE {} ESCAPE '\\'")
						args = append(args, "%"+wildcardReplacer.Replace(ext))
					}
					b.WriteString(")")
					extFilter = sq.Expr(b.String(), args...)
				}
				cursor, err := sq.FetchCursor(groupctxA, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
						" AND NOT is_dir" +
						" AND {extFilter} " +
						" ORDER BY file_path",
					Values: []any{
						sq.StringParam("outputDir", outputDir),
						sq.Param("extFilter", extFilter),
					},
				}, func(row *sq.Row) (result struct {
					FilePath string
					Text     []byte
				}) {
					result.FilePath = row.String("file_path")
					result.Text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
					return result
				})
				if err != nil {
					return stacktrace.New(err)
				}
				defer cursor.Close()
				subgroup, subctx := errgroup.WithContext(groupctxA)
				for cursor.Next() {
					result, err := cursor.Result()
					if err != nil {
						return stacktrace.New(err)
					}
					posts[i].Images = append(posts[i].Images, Image{
						Parent: path.Join("posts", posts[i].Category, posts[i].Name),
						Name:   path.Base(result.FilePath),
					})
					j := len(posts[i].Images) - 1
					subgroup.Go(func() (err error) {
						defer stacktrace.RecoverPanic(&err)
						defer func() {
							if len(result.Text) <= maxPoolableBufferCapacity {
								result.Text = result.Text[:0]
								bufPool.Put(bytes.NewBuffer(result.Text))
							}
						}()
						err = subctx.Err()
						if err != nil {
							return stacktrace.New(err)
						}
						var altText []byte
						result.Text = bytes.TrimSpace(result.Text)
						if bytes.HasPrefix(result.Text, []byte("!alt ")) {
							altText, result.Text, _ = bytes.Cut(result.Text, []byte("\n"))
							altText = bytes.TrimSpace(bytes.TrimPrefix(altText, []byte("!alt ")))
							result.Text = bytes.TrimSpace(result.Text)
						}
						posts[i].Images[j].AltText = string(altText)
						posts[i].Images[j].Caption = string(result.Text)
						return nil
					})
				}
				err = cursor.Close()
				if err != nil {
					return stacktrace.New(err)
				}
				err = subgroup.Wait()
				if err != nil {
					return err
				}
			} else {
				dirEntries, err := siteGen.fsys.WithContext(groupctxA).ReadDir(outputDir)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return stacktrace.New(err)
				}
				for _, dirEntry := range dirEntries {
					name := dirEntry.Name()
					if dirEntry.IsDir() {
						continue
					}
					fileType := AllowedFileTypes[path.Ext(name)]
					if fileType.Has(AttributeImg) {
						posts[i].Images = append(posts[i].Images, Image{
							Parent: path.Join("posts", posts[i].Category, posts[i].Name),
							Name:   name,
						})
					}
				}
			}
			return nil
		})
	}
	err := groupA.Wait()
	if err != nil {
		return err
	}
	postListData := PostListData{
		Site:       siteGen.Site,
		Category:   category,
		Pagination: NewPagination(currentPage, lastPage, 9),
		Posts:      posts,
	}
	outputDir := path.Join(siteGen.sitePrefix, "output/posts", postListData.Category)
	var outputFile string
	if currentPage == 1 {
		outputFile = path.Join(outputDir, "index.html")
	} else {
		outputFile = path.Join(outputDir, strconv.Itoa(currentPage), "index.html")
	}
	groupB, groupctxB := errgroup.WithContext(ctx)
	groupB.Go(func() error {
		writer, err := siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return stacktrace.New(err)
			}
			err := siteGen.fsys.WithContext(groupctxB).MkdirAll(path.Dir(outputFile), 0755)
			if err != nil {
				return stacktrace.New(err)
			}
			writer, err = siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
			if err != nil {
				return stacktrace.New(err)
			}
		}
		defer writer.Close()
		atomPath := "/" + path.Join("posts", category) + "/feed.atom"
		_, err = io.Copy(writer, strings.NewReader("<!DOCTYPE html>\n"+
			"<html lang='"+template.HTMLEscapeString(siteGen.Site.LanguageCode)+"'>\n"+
			"<meta charset='utf-8'>\n"+
			"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
			"<link rel='icon' href='"+template.HTMLEscapeString(string(siteGen.Site.Favicon))+"'>\n"+
			"<link rel='alternate' href='"+template.HTMLEscapeString(atomPath)+"' type='application/atom+xml'>\n",
		))
		if err != nil {
			return stacktrace.New(err)
		}
		var isDatabaseFS bool
		switch v := siteGen.fsys.(type) {
		case interface{ As(any) bool }:
			isDatabaseFS = v.As(&DatabaseFS{})
		}
		if siteGen.cdnDomain != "" && isDatabaseFS {
			pipeReader, pipeWriter := io.Pipe()
			result := make(chan error, 1)
			go func() {
				defer func() {
					if v := recover(); v != nil {
						result <- stacktrace.New(fmt.Errorf("panic: %v", v))
					}
				}()
				result <- siteGen.rewriteURLs(writer, pipeReader, "")
			}()
			err = tmpl.Execute(pipeWriter, postListData)
			if err != nil {
				templateErr := NewTemplateError(err)
				io.Copy(pipeWriter, strings.NewReader(html.EscapeString(templateErr.Error())))
				return templateErr
			}
			pipeWriter.Close()
			err = <-result
			if err != nil {
				return err
			}
		} else {
			err = tmpl.Execute(writer, postListData)
			if err != nil {
				templateErr := NewTemplateError(err)
				io.Copy(writer, strings.NewReader(html.EscapeString(templateErr.Error())))
				return templateErr
			}
		}
		err = writer.Close()
		if err != nil {
			return stacktrace.New(err)
		}
		return nil
	})
	if currentPage == 1 {
		groupB.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			outputFile := path.Join(outputDir, "1/index.html")
			writer, err := siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return stacktrace.New(err)
				}
				err := siteGen.fsys.WithContext(groupctxB).MkdirAll(path.Dir(outputFile), 0755)
				if err != nil {
					return stacktrace.New(err)
				}
				writer, err = siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
				if err != nil {
					return stacktrace.New(err)
				}
			}
			defer writer.Close()
			urlPath := "/" + path.Join("posts", category) + "/"
			_, err = io.Copy(writer, strings.NewReader("<!DOCTYPE html>\n"+
				"<html lang='"+template.HTMLEscapeString(siteGen.Site.LanguageCode)+"'>\n"+
				"<meta charset='utf-8'>\n"+
				"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
				"<meta http-equiv='refresh' content='0; url="+template.HTMLEscapeString(urlPath)+"'>\n"+
				"<title>redirect to "+urlPath+"</title>\n"+
				"<p>redirect to <a href='"+template.HTMLEscapeString(urlPath)+"'>"+urlPath+"</a></p>\n",
			))
			if err != nil {
				return stacktrace.New(err)
			}
			err = writer.Close()
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		})
		groupB.Go(func() (err error) {
			defer stacktrace.RecoverPanic(&err)
			scheme := "https://"
			var contentDomain string
			if strings.Contains(siteGen.sitePrefix, ".") {
				contentDomain = siteGen.sitePrefix
			} else {
				if !siteGen.contentDomainHTTPS {
					scheme = "http://"
				}
				if siteGen.sitePrefix != "" {
					contentDomain = strings.TrimPrefix(siteGen.sitePrefix, "@") + "." + siteGen.contentDomain
				} else {
					contentDomain = siteGen.contentDomain
				}
			}
			var title string
			if postListData.Category != "" {
				title = titleConverter.Title(urlSeparatorReplacer.Replace(postListData.Category)) + " - " + contentDomain
			} else {
				title = "Posts - " + contentDomain
			}
			feed := AtomFeed{
				Xmlns:   "http://www.w3.org/2005/Atom",
				ID:      scheme + contentDomain,
				Title:   title,
				Updated: time.Now().UTC().Format("2006-01-02 15:04:05Z"),
				Link: []AtomLink{{
					Href: scheme + contentDomain + "/" + path.Join("posts", postListData.Category) + "/feed.atom",
					Rel:  "self",
				}, {
					Href: scheme + contentDomain + "/" + path.Join("posts", postListData.Category) + "/",
					Rel:  "alternate",
				}},
				Entry: make([]AtomEntry, len(postListData.Posts)),
			}
			for i, post := range postListData.Posts {
				var postID string
				timestampPrefix, _, _ := strings.Cut(post.Name, "-")
				if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
					b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
					if len(b) == 5 && err == nil {
						// If we can figure out when a post was created, we can
						// use Tag URIs to create Atom Post IDs that are
						// resistant to URL changes (https://www.taguri.org/).
						// Example: tag:bokwoon.nbrew.net,2006-01-02:1jjdz28
						var timestamp [8]byte
						copy(timestamp[len(timestamp)-5:], b)
						post.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0).UTC()
						postID = "tag:" + contentDomain + "," + post.CreationTime.UTC().Format("2006-01-02") + ":" + timestampPrefix
					}
				}
				if postID == "" {
					postID = scheme + contentDomain + "/" + path.Join("posts", post.Category, post.Name) + "/"
				}
				var b strings.Builder
				pipeReader, pipeWriter := io.Pipe()
				result := make(chan error, 1)
				go func() {
					defer func() {
						if v := recover(); v != nil {
							result <- stacktrace.New(fmt.Errorf("panic: %v", v))
						}
					}()
					result <- siteGen.rewriteURLs(&b, pipeReader, path.Join("posts", post.Category, post.Name))
				}()
				err := siteGen.markdown.Convert([]byte(post.Content), pipeWriter)
				if err != nil {
					return stacktrace.New(err)
				}
				for _, image := range post.Images {
					_, err := io.Copy(pipeWriter, strings.NewReader("\n<div><img"+
						" src='"+template.HTMLEscapeString(image.Name)+"'"+
						" alt='"+template.HTMLEscapeString(image.AltText)+"'"+
						"></div>\n",
					))
					if err != nil {
						return stacktrace.New(err)
					}
					if len(image.Caption) > 0 {
						err := siteGen.markdown.Convert([]byte(image.Caption), pipeWriter)
						if err != nil {
							return stacktrace.New(err)
						}
					}
				}
				pipeWriter.Close()
				err = <-result
				if err != nil {
					return stacktrace.New(err)
				}
				feed.Entry[i] = AtomEntry{
					ID:        postID,
					Title:     post.Title,
					Published: post.CreationTime.UTC().Format("2006-01-02 15:04:05Z"),
					Updated:   post.ModificationTime.UTC().Format("2006-01-02 15:04:05Z"),
					Link: []AtomLink{{
						Href: scheme + contentDomain + "/" + path.Join("posts", post.Category, post.Name) + "/",
						Rel:  "alternate",
					}},
					Summary: AtomText{
						Type:    "text",
						Content: string(post.Preview),
					},
					Content: AtomCDATA{
						Type:    "html",
						Content: strings.ReplaceAll(b.String(), "]]>", "]]]]><![CDATA[>"), // https://stackoverflow.com/a/36331725
					},
				}
			}
			writer, err := siteGen.fsys.WithContext(groupctxB).OpenWriter(path.Join(outputDir, "feed.atom"), 0644)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return stacktrace.New(err)
				}
				err := siteGen.fsys.WithContext(groupctxB).MkdirAll(outputDir, 0755)
				if err != nil {
					return stacktrace.New(err)
				}
				writer, err = siteGen.fsys.WithContext(groupctxB).OpenWriter(path.Join(outputDir, "feed.atom"), 0644)
				if err != nil {
					return stacktrace.New(err)
				}
			}
			defer writer.Close()
			_, err = writer.Write([]byte(xml.Header))
			if err != nil {
				return stacktrace.New(err)
			}
			encoder := xml.NewEncoder(writer)
			encoder.Indent("", "  ")
			err = encoder.Encode(&feed)
			if err != nil {
				return stacktrace.New(err)
			}
			err = writer.Close()
			if err != nil {
				return stacktrace.New(err)
			}
			return nil
		})
	}
	err = groupB.Wait()
	if err != nil {
		return err
	}
	return nil
}

// TemplateError is used to represent an error when parsing or executing a
// template.
type TemplateError struct {
	// Name of the template that caused the error.
	Name string `json:"name"`

	// Line number in the template that caused the error.
	Line int `json:"line"`

	// ErrorMessage of the error.
	ErrorMessage string `json:"errorMessage"`
}

// NewTemplateError constructs a new TemplateError from an error returned by
// the html/template package by parsing the error string, which is
// unfortunately the only way we can extract the template name and line number.
func NewTemplateError(err error) error {
	sections := strings.SplitN(err.Error(), ":", 4)
	if len(sections) < 4 || strings.TrimSpace(sections[0]) != "template" {
		return TemplateError{
			ErrorMessage: err.Error(),
		}
	}
	templateName := strings.TrimSpace(sections[1])
	lineNo, _ := strconv.Atoi(strings.TrimSpace(sections[2]))
	errorMessage := strings.TrimSpace(sections[3])
	i := strings.Index(errorMessage, ":")
	if i > 0 {
		colNo, _ := strconv.Atoi(strings.TrimSpace(errorMessage[:i]))
		if colNo > 0 {
			errorMessage = strings.TrimSpace(errorMessage[i+1:])
		}
	}
	return TemplateError{
		Name:         templateName,
		Line:         lineNo,
		ErrorMessage: errorMessage,
	}
}

// Error implements the error interface.
func (templateErr TemplateError) Error() string {
	if templateErr.Name == "" {
		return templateErr.ErrorMessage
	}
	if templateErr.Line == 0 {
		return templateErr.Name + ": " + templateErr.ErrorMessage
	}
	return templateErr.Name + ":" + strconv.Itoa(templateErr.Line) + ": " + templateErr.ErrorMessage
}

// rewriteURLs parses a stream of incoming HTML from a reader and writes it
// into a writer, rewriting any image URLs it finds to use the CDN domain
// instead.
func (siteGen *SiteGenerator) rewriteURLs(writer io.Writer, reader io.Reader, urlPath string) error {
	tokenizer := html.NewTokenizer(reader)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return nil
			}
			return stacktrace.New(err)
		case html.TextToken:
			_, err := writer.Write(tokenizer.Raw())
			if err != nil {
				return stacktrace.New(err)
			}
		case html.DoctypeToken:
			for _, b := range [...][]byte{
				[]byte("<!DOCTYPE "), tokenizer.Raw(), []byte(">"),
			} {
				_, err := writer.Write(b)
				if err != nil {
					return stacktrace.New(err)
				}
			}
		case html.CommentToken:
			for _, b := range [...][]byte{
				[]byte("<!--"), tokenizer.Raw(), []byte("-->"),
			} {
				_, err := writer.Write(b)
				if err != nil {
					return stacktrace.New(err)
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			switch tokenType {
			case html.StartTagToken, html.SelfClosingTagToken:
				_, err := writer.Write([]byte("<"))
				if err != nil {
					return stacktrace.New(err)
				}
			case html.EndTagToken:
				_, err := writer.Write([]byte("</"))
				if err != nil {
					return stacktrace.New(err)
				}
			}
			var key, val []byte
			name, moreAttr := tokenizer.TagName()
			_, err := writer.Write(name)
			if err != nil {
				return stacktrace.New(err)
			}
			isImgTag := bytes.Equal(name, []byte("img"))
			isAnchorTag := bytes.Equal(name, []byte("a"))
			for moreAttr {
				key, val, moreAttr = tokenizer.TagAttr()
				if (isImgTag && bytes.Equal(key, []byte("src"))) || (isAnchorTag && bytes.Equal(key, []byte("href"))) {
					rawURL := string(val)
					fileType := AllowedFileTypes[path.Ext(rawURL)]
					if fileType.Has(AttributeObject) {
						uri, err := url.Parse(rawURL)
						if err == nil && uri.Scheme == "" && uri.Host == "" {
							fileType := AllowedFileTypes[path.Ext(uri.Path)]
							if fileType.Has(AttributeImg) {
								uri.Scheme = ""
								uri.Host = siteGen.cdnDomain
								if strings.HasPrefix(uri.Path, "/") {
									filePath := path.Join(siteGen.sitePrefix, "output", uri.Path)
									if fileID, ok := siteGen.imgFileIDs[filePath]; ok {
										uri.Path = "/" + fileID.String() + path.Ext(filePath)
										val = []byte(uri.String())
									}
								} else {
									filePath := path.Join(siteGen.sitePrefix, "output", urlPath, uri.Path)
									if fileID, ok := siteGen.imgFileIDs[filePath]; ok {
										uri.Path = "/" + fileID.String() + path.Ext(filePath)
										val = []byte(uri.String())
									}
								}
							}
						}
					}
				}
				for _, b := range [...][]byte{
					[]byte(` `), key, []byte(`="`), bytes.ReplaceAll(val, []byte("\""), []byte("&quot;")), []byte(`"`),
				} {
					_, err := writer.Write(b)
					if err != nil {
						return stacktrace.New(err)
					}
				}
			}
			switch tokenType {
			case html.StartTagToken, html.EndTagToken:
				_, err = writer.Write([]byte(">"))
				if err != nil {
					return stacktrace.New(err)
				}
			case html.SelfClosingTagToken:
				_, err = writer.Write([]byte("/>"))
				if err != nil {
					return stacktrace.New(err)
				}
			}
		}
	}
}

// baseFuncMap is the base funcMap used for all user templates.
var baseFuncMap = map[string]any{
	"dump": func(x any) template.HTML {
		return template.HTML("<pre>" + template.HTMLEscapeString(spew.Sdump(x)) + "</pre>")
	},
	"join": func(args ...any) (string, error) {
		s := make([]string, len(args))
		for i, v := range args {
			switch v := v.(type) {
			case string:
				s[i] = v
			case int:
				s[i] = strconv.Itoa(v)
			case int64:
				s[i] = strconv.FormatInt(v, 10)
			case float64:
				s[i] = strconv.Itoa(int(v))
			default:
				return "", fmt.Errorf("not a string or number: %#v", v)
			}
		}
		return path.Join(s...), nil
	},
	"list": func(args ...any) []any { return args },
	"map": func(keyvalue ...any) (map[string]any, error) {
		m := make(map[string]any)
		if len(m)%2 != 0 {
			return nil, fmt.Errorf("odd number of arguments passed in")
		}
		for i := 0; i+1 < len(keyvalue); i += 2 {
			key, ok := keyvalue[i].(string)
			if !ok {
				return nil, fmt.Errorf("key is not a string: %#v", keyvalue[i])
			}
			m[key] = keyvalue[i+1]
		}
		return m, nil
	},
	"safeHTML": func(x any) template.HTML {
		switch x := x.(type) {
		case nil:
			return ""
		case string:
			return template.HTML(x)
		default:
			return template.HTML(fmt.Sprint(x))
		}
	},
	"formatTime": func(t, layout, offset any) string {
		if t, ok := t.(time.Time); ok {
			if layout, ok := layout.(string); ok {
				switch offset := offset.(type) {
				case int:
					return t.In(time.FixedZone("", offset)).Format(layout)
				case int64:
					return t.In(time.FixedZone("", int(offset))).Format(layout)
				case float64:
					return t.In(time.FixedZone("", int(offset))).Format(layout)
				default:
					return fmt.Sprintf("not a number: %#v", offset)
				}
			}
			return fmt.Sprintf("not a string: %#v", layout)
		}
		return fmt.Sprintf("not a time.Time: %#v", t)
	},
	"htmlHeadings": func(x any) ([]Heading, error) {
		switch x := x.(type) {
		case string:
			return htmlHeadings(strings.NewReader(x))
		case template.HTML:
			return htmlHeadings(strings.NewReader(string(x)))
		default:
			return nil, fmt.Errorf("note a string or template.HTML: %#v", x)
		}
	},
	"case": func(expr any, args ...any) any {
		var fallback any
		if len(args)%2 == 0 {
			fallback = ""
		} else {
			fallback = args[len(args)-1]
			args = args[:len(args)-1]
		}
		for i := 0; i+1 < len(args); i += 2 {
			if reflect.DeepEqual(expr, args[i]) {
				return args[i+1]
			}
		}
		return fallback
	},
	"casewhen": func(args ...any) any {
		var fallback any
		if len(args)%2 == 0 {
			fallback = ""
		} else {
			fallback = args[len(args)-1]
			args = args[:len(args)-1]
		}
		for i := 0; i+1 < len(args); i += 2 {
			if truth, _ := template.IsTrue(args[i]); truth {
				return args[i+1]
			}
		}
		return fallback
	},
	"hasPrefix": func(str, prefix any) (bool, error) {
		if str, ok := str.(string); ok {
			if prefix, ok := prefix.(string); ok {
				return strings.HasPrefix(str, prefix), nil
			}
			return false, fmt.Errorf("not a string: %#v", prefix)
		}
		return false, fmt.Errorf("not a string: %#v", str)
	},
	"hasSuffix": func(str, suffix any) (bool, error) {
		if str, ok := str.(string); ok {
			if suffix, ok := suffix.(string); ok {
				return strings.HasSuffix(str, suffix), nil
			}
			return false, fmt.Errorf("not a string: %#v", suffix)
		}
		return false, fmt.Errorf("not a string: %#v", str)
	},
	"trimPrefix": func(str, prefix any) (string, error) {
		if str, ok := str.(string); ok {
			if prefix, ok := prefix.(string); ok {
				return strings.TrimPrefix(str, prefix), nil
			}
			return "", fmt.Errorf("not a string: %#v", prefix)
		}
		return "", fmt.Errorf("not a string: %#v", str)
	},
	"trimSuffix": func(str, suffix any) (string, error) {
		if str, ok := str.(string); ok {
			if suffix, ok := suffix.(string); ok {
				return strings.TrimSuffix(str, suffix), nil
			}
			return "", fmt.Errorf("not a string: %#v", suffix)
		}
		return "", fmt.Errorf("not a string: %#v", str)
	},
	"trimSpace": func(x any) (string, error) {
		if x, ok := x.(string); ok {
			return strings.TrimSpace(x), nil
		}
		return "", fmt.Errorf("not a string: %#v", x)
	},
	"replace": func(str any, replacements ...any) (string, error) {
		if str, ok := str.(string); ok {
			if len(replacements)%2 != 0 {
				return "", fmt.Errorf("odd number of replacements passed in")
			}
			if len(replacements) == 2 {
				if before, ok := replacements[0].(string); ok {
					if after, ok := replacements[1].(string); ok {
						return strings.ReplaceAll(str, before, after), nil
					}
					return "", fmt.Errorf("not a string: %#v", replacements[1])
				}
				return "", fmt.Errorf("not a string: %#v", replacements[0])
			}
			beforeafter := make([]string, 0, len(replacements))
			for i := 0; i+1 < len(replacements); i += 2 {
				before, ok := replacements[i].(string)
				if !ok {
					return "", fmt.Errorf("not a string: %#v", replacements[i])
				}
				after, ok := replacements[i+1].(string)
				if !ok {
					return "", fmt.Errorf("not a string: %#v", replacements[i+1])
				}
				beforeafter = append(beforeafter, before, after)
			}
			return strings.NewReplacer(beforeafter...).Replace(str), nil
		}
		return "", fmt.Errorf("not a string: %#v", str)
	},
	"title": func(x any) (string, error) {
		if x, ok := x.(string); ok {
			return titleConverter.Title(x), nil
		}
		return "", fmt.Errorf("not a string: %#v", x)
	},
	"trimHead": func(str, sep any) (string, error) {
		if str, ok := str.(string); ok {
			if sep, ok := sep.(string); ok {
				_, tail, _ := strings.Cut(str, sep)
				return tail, nil
			}
			return "", fmt.Errorf("not a string: %#v", sep)
		}
		return "", fmt.Errorf("not a string: %#v", str)
	},
	"trimTail": func(str, sep any) (string, error) {
		if str, ok := str.(string); ok {
			if sep, ok := sep.(string); ok {
				head, _, _ := strings.Cut(str, sep)
				return head, nil
			}
			return "", fmt.Errorf("not a string: %#v", sep)
		}
		return "", fmt.Errorf("not a string: %#v", str)
	},
	"base": func(x any) (string, error) {
		if x, ok := x.(string); ok {
			return path.Base(x), nil
		}
		return "", fmt.Errorf("not a string: %#v", x)
	},
	"ext": func(x any) (string, error) {
		if x, ok := x.(string); ok {
			return path.Ext(x), nil
		}
		return "", fmt.Errorf("not a string: %#v", x)
	},
	"seq": func(args ...any) ([]int, error) {
		first, increment, last := 1, 1, 1
		switch len(args) {
		case 0:
			return nil, fmt.Errorf("need at least one argument")
		case 1:
			switch n := args[0].(type) {
			case int:
				last = n
			case int64:
				last = int(n)
			case float64:
				last = int(n)
			default:
				return nil, fmt.Errorf("not a number: %#v", args[0])
			}
		case 2:
			switch n := args[0].(type) {
			case int:
				first = n
			case int64:
				first = int(n)
			case float64:
				first = int(n)
			default:
				return nil, fmt.Errorf("not a number: %#v", args[0])
			}
			switch n := args[1].(type) {
			case int:
				last = n
			case int64:
				last = int(n)
			case float64:
				last = int(n)
			default:
				return nil, fmt.Errorf("not a number: %#v", args[1])
			}
		case 3:
			switch n := args[0].(type) {
			case int:
				first = n
			case int64:
				first = int(n)
			case float64:
				first = int(n)
			default:
				return nil, fmt.Errorf("not a number: %#v", args[0])
			}
			switch n := args[1].(type) {
			case int:
				increment = n
			case int64:
				increment = int(n)
			case float64:
				increment = int(n)
			default:
				return nil, fmt.Errorf("not a number: %#v", args[1])
			}
			switch n := args[2].(type) {
			case int:
				last = n
			case int64:
				last = int(n)
			case float64:
				last = int(n)
			default:
				return nil, fmt.Errorf("not a number: %#v", args[2])
			}
		default:
			return nil, fmt.Errorf("too many arguments (max 3)")
		}
		if first == last || increment == 0 {
			return []int{first}, nil
		}
		if first < last && increment < 0 || first > last && increment > 0 {
			return nil, fmt.Errorf("infinite sequence")
		}
		length := ((last - first + 1) / increment) + 1
		if length < 0 {
			length = -length
		}
		nums := make([]int, 0, length)
		for num := first; num <= last; num += increment {
			if len(nums) > 2000 {
				return nums, nil
			}
			nums = append(nums, num)
		}
		return nums, nil
	},
	"plus": func(args ...any) (any, error) {
		var intCount, floatCount, stringCount int
		for _, arg := range args {
			switch arg.(type) {
			case int, int64:
				intCount++
			case float64:
				floatCount++
			case string:
				stringCount++
			case template.HTML:
				stringCount++
			default:
				return nil, fmt.Errorf("not an int, float or string: %#v", arg)
			}
		}
		if intCount == len(args) {
			var result int
			for _, arg := range args {
				switch arg := arg.(type) {
				case int:
					result += arg
				case int64:
					result += int(arg)
				}
			}
			return result, nil
		}
		if intCount+floatCount == len(args) {
			var result float64
			for _, arg := range args {
				switch arg := arg.(type) {
				case int:
					result += float64(arg)
				case int64:
					result += float64(arg)
				case float64:
					result += arg
				}
			}
			return result, nil
		}
		var b strings.Builder
		for _, arg := range args {
			switch arg := arg.(type) {
			case int:
				b.WriteString(strconv.Itoa(arg))
			case int64:
				b.WriteString(strconv.FormatInt(arg, 10))
			case float64:
				b.WriteString(strconv.FormatFloat(arg, 'f', -1, 64))
			case string:
				b.WriteString(arg)
			case template.HTML:
				b.WriteString(string(arg))
			}
		}
		return b.String(), nil
	},
	"minus": func(args ...any) (any, error) {
		var intCount, floatCount int
		for _, arg := range args {
			switch arg.(type) {
			case int, int64:
				intCount++
			case float64:
				floatCount++
			default:
				return nil, fmt.Errorf("not an int or float: %#v", arg)
			}
		}
		if intCount == len(args) {
			var result int
			for i, arg := range args {
				if i == 0 {
					switch arg := arg.(type) {
					case int:
						result = arg
					case int64:
						result = int(arg)
					}
					if len(args) == 1 {
						return -result, nil
					}
				} else {
					switch arg := arg.(type) {
					case int:
						result -= arg
					case int64:
						result -= int(arg)
					}
				}
			}
			return result, nil
		}
		var result float64
		for i, arg := range args {
			if i == 0 {
				switch arg := arg.(type) {
				case int:
					result = float64(arg)
				case int64:
					result = float64(arg)
				case float64:
					result = arg
				}
				if len(args) == 1 {
					return -result, nil
				}
			} else {
				switch arg := arg.(type) {
				case int:
					result -= float64(arg)
				case int64:
					result -= float64(arg)
				case float64:
					result -= arg
				}
			}
		}
		return result, nil
	},
}

// Heading represents a markdown heading.
type Heading struct {
	// ID of the heading.
	ID string

	// Title of the heading.
	Title string

	// Level of the heading i.e. for h1 - h6.
	Level int

	// Subheadings of the heading.
	Subheadings []Heading

	// Running count of the heading.
	Position int
}

// htmlHeadings parses a stream of HTML from a reader and returns a list of
// headings (nested appropriately) that have an id defined on them.
func htmlHeadings(r io.Reader) ([]Heading, error) {
	var headingLevel, position int
	var headingID string
	var headingTitle bytes.Buffer
	// parents[1] to parents[6] correspond to the latest h1 - h6 parents.
	// parents[0] is the root parent i.e. h0.
	var parents [1 + 6]*Heading
	parents[0] = &Heading{}
	tokenizer := html.NewTokenizer(r)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return parents[0].Subheadings, nil
			}
			return nil, err
		case html.StartTagToken:
			var level int
			name, moreAttr := tokenizer.TagName()
			switch string(name) {
			case "h1":
				level = 1
			case "h2":
				level = 2
			case "h3":
				level = 3
			case "h4":
				level = 4
			case "h5":
				level = 5
			case "h6":
				level = 6
			default:
				continue
			}
			var key, val []byte
			for moreAttr {
				key, val, moreAttr = tokenizer.TagAttr()
				if string(key) == "id" {
					headingID = string(val)
					headingLevel = level
					break
				}
			}
		case html.TextToken:
			if headingID != "" {
				headingTitle.Write(tokenizer.Raw())
			}
		case html.EndTagToken:
			name, _ := tokenizer.TagName()
			switch string(name) {
			case "h1":
				if headingLevel != 1 {
					continue
				}
			case "h2":
				if headingLevel != 2 {
					continue
				}
			case "h3":
				if headingLevel != 3 {
					continue
				}
			case "h4":
				if headingLevel != 4 {
					continue
				}
			case "h5":
				if headingLevel != 5 {
					continue
				}
			case "h6":
				if headingLevel != 6 {
					continue
				}
			default:
				continue
			}
			position++
			heading := Heading{
				Title:    headingTitle.String(),
				ID:       headingID,
				Level:    headingLevel,
				Position: position,
			}
			var mostRecentParent *Heading
			for i := heading.Level - 1; i >= 0; i-- {
				parent := parents[i]
				if parent == nil {
					continue
				}
				if mostRecentParent == nil || parent.Position > mostRecentParent.Position {
					mostRecentParent = parent
				}
			}
			mostRecentParent.Subheadings = append(mostRecentParent.Subheadings, heading)
			n := len(mostRecentParent.Subheadings) - 1
			parents[heading.Level] = &mostRecentParent.Subheadings[n]
			headingTitle.Reset()
			headingID = ""
			headingLevel = 0
		}
	}
}

// Pagination represents the pagination information for a post list.
type Pagination struct {
	// First page.
	First int

	// Previous page.
	Previous int

	// Current page.
	Current int

	// Next page.
	Next int

	// Last page.
	Last int

	// Numbers is the list of page numbers to display.
	Numbers []int
}

// NewPagination constructs a new pagination for a given range of pages.
func NewPagination(currentPage, lastPage, visiblePages int) Pagination {
	const numConsecutiveNeighbours = 2
	if visiblePages%2 == 0 {
		panic("even number of visiblePages")
	}
	minVisiblePages := (numConsecutiveNeighbours * 2) + 1
	if visiblePages < minVisiblePages {
		panic("visiblePages cannot be lower than " + strconv.Itoa(minVisiblePages))
	}
	pagination := Pagination{
		First:   1,
		Current: currentPage,
		Last:    lastPage,
	}
	previous := currentPage - 1
	if previous >= 1 {
		pagination.Previous = previous
	}
	next := currentPage + 1
	if next <= lastPage {
		pagination.Next = (next)
	}
	// If there are fewer pages than visible pages, iterate through all the
	// page numbers.
	if lastPage <= visiblePages {
		pagination.Numbers = make([]int, 0, lastPage)
		for page := 1; page <= lastPage; page++ {
			pagination.Numbers = append(pagination.Numbers, page)
		}
		return pagination
	}
	// Slots corresponds to the available slots in pagination.Numbers, storing
	// the page numbers as integers. They will be converted to strings later.
	slots := make([]int, visiblePages)
	// A unit is a tenth of the maximum number of pages. The rationale is that
	// users should have to paginate at most 10 such units to get from start to
	// end, no matter how many pages there are.
	unit := lastPage / 10
	if currentPage-1 < len(slots)>>1 {
		// If there are fewer pages on the left than half of the slots, the
		// current page will skew more towards the left. We fill in consecutive
		// page numbers from left to right, then fill in the remaining slots.
		numConsecutive := (currentPage - 1) + 1 + numConsecutiveNeighbours
		consecutiveStart := 0
		consecutiveEnd := numConsecutive - 1
		page := 1
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[consecutiveEnd+1 : len(slots)-1]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else if lastPage-currentPage < len(slots)>>1 {
		// If there are fewer pages on the right than half of the slots, the
		// current page will skew more towards the right. We fill in
		// consecutive page numbers from the right to left, then fill in the
		// remaining slots.
		numConsecutive := (lastPage - currentPage) + 1 + numConsecutiveNeighbours
		consecutiveStart := len(slots) - 1
		consecutiveEnd := len(slots) - numConsecutive
		page := lastPage
		for i := consecutiveStart; i >= consecutiveEnd; i-- {
			slots[i] = page
			page -= 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[1:consecutiveEnd]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveEnd; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else {
		// If we reach here, it means the current page is directly in the
		// center the slots. Fill in the consecutive band of numbers around the
		// center, then fill in the remaining slots to the left and to the
		// right.
		consecutiveStart := len(slots)>>1 - numConsecutiveNeighbours
		consecutiveEnd := len(slots)>>1 + numConsecutiveNeighbours
		page := currentPage - numConsecutiveNeighbours
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots on the left with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots := slots[1:consecutiveStart]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveStart; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
		// Fill in the remaining slots on the right with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots = slots[consecutiveEnd+1 : len(slots)-1]
		delta = numConsecutiveNeighbours + len(remainingSlots)
		shift = 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	}
	// Convert the page numbers in the slots to strings.
	pagination.Numbers = slots
	return pagination
}

// AtomFeed represents an atom feed (i.e. a list of posts).
type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Link    []AtomLink  `xml:"link"`
	Entry   []AtomEntry `xml:"entry"`
}

// AtomEntry represents an atom entry (i.e. a post).
type AtomEntry struct {
	ID        string     `xml:"id"`
	Title     string     `xml:"title"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
	Link      []AtomLink `xml:"link"`
	Summary   AtomText   `xml:"summary"`
	Content   AtomCDATA  `xml:"content"`
}

// AtomLink represents an atom link.
type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

// AtomText represents some text in atom.
type AtomText struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// AtomCDATA represents CDATA in atom.
type AtomCDATA struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",cdata"`
}

// PostTemplate returns the post template for a category.
func (siteGen *SiteGenerator) PostTemplate(ctx context.Context, category string) (*template.Template, error) {
	if strings.Contains(category, "/") {
		return nil, stacktrace.New(fmt.Errorf("invalid post category"))
	}
	var text string
	var found bool
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	if isDatabaseFS {
		result, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", path.Join(siteGen.sitePrefix, "posts", category, "post.html")),
			},
		}, func(row *sq.Row) sql.NullString {
			return row.NullString("text")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, stacktrace.New(err)
		}
		text = result.String
		found = result.Valid
	} else {
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "posts", category, "post.html"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, stacktrace.New(err)
			}
		} else {
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return nil, stacktrace.New(err)
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, stacktrace.New(err)
			}
			err = file.Close()
			if err != nil {
				return nil, stacktrace.New(err)
			}
			text = b.String()
			found = true
		}
	}
	if !found {
		file, err := RuntimeFS.Open("embed/post.html")
		if err != nil {
			return nil, stacktrace.New(err)
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, stacktrace.New(err)
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return nil, stacktrace.New(err)
		}
		err = file.Close()
		if err != nil {
			return nil, stacktrace.New(err)
		}
		text = b.String()
	}
	tmpl, err := siteGen.ParseTemplate(ctx, path.Join("posts", category, "post.html"), text)
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}

// PostListTemplate returns the post list template for a category.
func (siteGen *SiteGenerator) PostListTemplate(ctx context.Context, category string) (*template.Template, error) {
	if strings.Contains(category, "/") {
		return nil, stacktrace.New(fmt.Errorf("invalid post category"))
	}
	var err error
	var text string
	var found bool
	databaseFS, isDatabaseFS := &DatabaseFS{}, false
	switch v := siteGen.fsys.(type) {
	case interface{ As(any) bool }:
		isDatabaseFS = v.As(&databaseFS)
	}
	if isDatabaseFS {
		result, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", path.Join(siteGen.sitePrefix, "posts", category, "postlist.html")),
			},
		}, func(row *sq.Row) sql.NullString {
			return row.NullString("text")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, stacktrace.New(err)
		}
		text = result.String
		found = result.Valid
	} else {
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "posts", category, "postlist.html"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, stacktrace.New(err)
			}
		} else {
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return nil, stacktrace.New(err)
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, stacktrace.New(err)
			}
			err = file.Close()
			if err != nil {
				return nil, stacktrace.New(err)
			}
			text = b.String()
			found = true
		}
	}
	if !found {
		file, err := RuntimeFS.Open("embed/postlist.html")
		if err != nil {
			return nil, stacktrace.New(err)
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, stacktrace.New(err)
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return nil, stacktrace.New(err)
		}
		err = file.Close()
		if err != nil {
			return nil, stacktrace.New(err)
		}
		text = b.String()
	}
	tmpl, err := siteGen.ParseTemplate(ctx, path.Join("posts", category, "postlist.html"), text)
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}
