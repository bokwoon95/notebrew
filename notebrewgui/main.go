package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/bokwoon95/notebrew"
)

type FilesConfig struct {
	Provider string `json:"provider"`
	FilePath string `json:"filePath"`
}

func main() {
	var gui GUI
	gui.App = app.New()
	gui.Window = gui.App.NewWindow("Notebrew")
	gui.Window.Resize(fyne.NewSize(600, 450))
	gui.Window.CenterOnScreen()
	gui.StartServer = make(chan struct{})
	gui.StopServer = make(chan struct{})
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		// contentdomain.txt
		configDir := filepath.Join(homeDir, "notebrew-config")
		b, err := os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		contentDomain := string(bytes.TrimSpace(b))
		if contentDomain == "" {
			contentDomain = "example.com"
		}
		// port.txt
		b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
		}
		port := string(bytes.TrimSpace(b))
		_, err = strconv.Atoi(port)
		if err != nil {
			port = "6444"
		}
		// files.json
		b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		b = bytes.TrimSpace(b)
		var filesConfig FilesConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			err = decoder.Decode(&filesConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
			}
		}
		if filesConfig.FilePath == "" {
			filesConfig.FilePath = filepath.Join(homeDir, "notebrew-files")
		}
		// Logger.
		logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: true,
		})
		gui.Logger = slog.New(logHandler).With(slog.String("version", notebrew.Version))
		// Widgets.
		gui.ContentDomainLabel = widget.NewLabel("Blog URL:")
		gui.ContentDomainEntry = widget.NewEntry()
		gui.ContentDomainEntry.SetPlaceHolder("your site URL e.g. example.com")
		gui.ContentDomainEntry.SetText(contentDomain)
		gui.PortLabel = widget.NewLabel("Port:")
		gui.PortEntry = widget.NewEntry()
		gui.PortEntry.SetPlaceHolder("port that Notebrew listens on e.g. 6444")
		gui.PortEntry.SetText(port)
		gui.FolderValueLabel = widget.NewLabel(filesConfig.FilePath)
		gui.FolderLabel = widget.NewLabel("Folder:")
		gui.FolderValueLabel = widget.NewLabel(filesConfig.FilePath)
		gui.FolderButton = widget.NewButton("📂", func() {
			// Open folder dialog
			folderDialog := dialog.NewFolderOpen(
				func(uri fyne.ListableURI, err error) {
					if err != nil {
						dialog.ShowError(err, gui.Window)
						return
					}
					if uri == nil {
						// No folder selected, so just return
						return
					}
					// Display the selected folder path
					gui.FolderValueLabel.SetText(uri.Path())
				},
				gui.Window,
			)
			// Show the folder dialog
			folderDialog.Show()
		})
		gui.StartButton = widget.NewButton("Start Notebrew ▶", func() {
			select {
			case gui.StartServer <- struct{}{}:
			default:
			}
		})
		gui.StopButton = widget.NewButton("Stop Notebrew 🛑", func() {
			select {
			case gui.StopServer <- struct{}{}:
			default:
			}
		})
		gui.StopButton.Disable()
		gui.OpenBrowserButton = widget.NewButton("Open Browser 🌐", func() {
			switch runtime.GOOS {
			case "linux":
				exec.Command("xdg-open", "http://localhost:"+gui.PortEntry.Text+"/files/").Start()
			case "windows":
				exec.Command("explorer.exe", "http://localhost:"+gui.PortEntry.Text+"/files/").Start()
			case "darwin":
				exec.Command("open", "http://localhost:"+gui.PortEntry.Text+"/files/").Start()
			}
		})
		gui.OpenBrowserButton.Disable()
		gui.Window.SetContent(container.NewVBox(
			container.New(layout.NewFormLayout(),
				gui.ContentDomainLabel, gui.ContentDomainEntry,
				gui.PortLabel, gui.PortEntry,
				gui.FolderLabel, container.NewHBox(gui.FolderValueLabel, layout.NewSpacer(), gui.FolderButton),
			),
			container.NewGridWithColumns(2, gui.StartButton, gui.StopButton),
			gui.OpenBrowserButton,
		))
		go gui.ServerLoop(configDir)
		gui.Window.ShowAndRun()
		return nil
	}()
	if err != nil {
		gui.Window.SetTitle("Error starting notebrew")
		gui.Window.SetContent(widget.NewLabel(err.Error()))
		gui.Window.ShowAndRun()
		os.Exit(1)
	}
}

type GUI struct {
	App                fyne.App
	Window             fyne.Window
	Logger             *slog.Logger
	StartServer        chan struct{}
	StopServer         chan struct{}
	ContentDomainLabel *widget.Label
	ContentDomainEntry *widget.Entry
	PortLabel          *widget.Label
	PortEntry          *widget.Entry
	FolderLabel        *widget.Label
	FolderValueLabel   *widget.Label
	FolderButton       *widget.Button
	StartButton        *widget.Button
	StopButton         *widget.Button
	OpenBrowserButton  *widget.Button
}

func (gui *GUI) ServerLoop(configDir string) {
	var nbrew *notebrew.Notebrew
	var server *http.Server
	for {
		select {
		case <-gui.StartServer:
			err := os.MkdirAll(configDir, 0755)
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			err = os.WriteFile(filepath.Join(configDir, "contentdomain.txt"), []byte(gui.ContentDomainEntry.Text), 0644)
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			port, err := strconv.Atoi(gui.PortEntry.Text)
			if err != nil {
				gui.PortEntry.SetText("6444")
				port = 6444
			}
			err = os.WriteFile(filepath.Join(configDir, "port.txt"), []byte(gui.PortEntry.Text), 0644)
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			b, err := json.Marshal(FilesConfig{
				Provider: "directory",
				FilePath: gui.FolderValueLabel.Text,
			})
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			err = os.WriteFile(filepath.Join(configDir, "files.json"), b, 0644)
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			nbrew = notebrew.New()
			nbrew.Logger = gui.Logger
			nbrew.CMSDomain = "localhost:" + gui.PortEntry.Text
			nbrew.ContentDomain = gui.ContentDomainEntry.Text
			nbrew.ContentDomainHTTPS = true
			nbrew.Port = port
			directoryFS, err := notebrew.NewDirectoryFS(notebrew.DirectoryFSConfig{
				RootDir: gui.FolderValueLabel.Text,
			})
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			nbrew.FS = directoryFS
			for _, dir := range []string{
				"notes",
				"pages",
				"posts",
				"output",
				"output/posts",
				"output/themes",
				"imports",
				"exports",
			} {
				err := nbrew.FS.Mkdir(dir, 0755)
				if err != nil && !errors.Is(err, fs.ErrExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			_, err = fs.Stat(nbrew.FS, "site.json")
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
				siteConfig := notebrew.SiteConfig{
					LanguageCode:   "en",
					Title:          "My Blog",
					Tagline:        "",
					Emoji:          "☕️",
					Favicon:        "",
					CodeStyle:      "onedark",
					TimezoneOffset: "+00:00",
					Description:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
					NavigationLinks: []notebrew.NavigationLink{{
						Name: "Home",
						URL:  "/",
					}, {
						Name: "Posts",
						URL:  "/posts/",
					}},
				}
				b, err := json.MarshalIndent(&siteConfig, "", "  ")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				writer, err := nbrew.FS.OpenWriter("site.json", 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				defer writer.Close()
				_, err = io.Copy(writer, bytes.NewReader(b))
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = writer.Close()
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			_, err = fs.Stat(nbrew.FS, "posts/postlist.json")
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
				b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/postlist.json")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				writer, err := nbrew.FS.OpenWriter("posts/postlist.json", 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = writer.Close()
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			siteGen, err := notebrew.NewSiteGenerator(context.Background(), notebrew.SiteGeneratorConfig{
				FS:                 nbrew.FS,
				ContentDomain:      nbrew.ContentDomain,
				ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
				CDNDomain:          nbrew.CDNDomain,
				SitePrefix:         "",
			})
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			_, err = fs.Stat(nbrew.FS, "pages/index.html")
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
				b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/index.html")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				writer, err := nbrew.FS.OpenWriter("pages/index.html", 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = writer.Close()
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				creationTime := time.Now()
				err = siteGen.GeneratePage(context.Background(), "pages/index.html", string(b), creationTime, creationTime)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			_, err = fs.Stat(nbrew.FS, "pages/404.html")
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
				b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/404.html")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				writer, err := nbrew.FS.OpenWriter("pages/404.html", 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = writer.Close()
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				creationTime := time.Now()
				err = siteGen.GeneratePage(context.Background(), "pages/404.html", string(b), creationTime, creationTime)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			_, err = fs.Stat(nbrew.FS, "posts/post.html")
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
				b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/post.html")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				writer, err := nbrew.FS.OpenWriter("posts/post.html", 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = writer.Close()
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			_, err = fs.Stat(nbrew.FS, "posts/postlist.html")
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					dialog.ShowError(err, gui.Window)
					return
				}
				b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/postlist.html")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				writer, err := nbrew.FS.OpenWriter("posts/postlist.html", 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = writer.Close()
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				tmpl, err := siteGen.PostListTemplate(context.Background(), "")
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}
			// Content Security Policy.
			nbrew.ContentSecurityPolicy = "default-src 'none';" +
				" script-src 'self' 'unsafe-hashes' " + notebrew.BaselineJSHash + ";" +
				" connect-src 'self';" +
				" img-src 'self' data:;" +
				" style-src 'self' 'unsafe-inline';" +
				" base-uri 'self';" +
				" form-action 'self';" +
				" manifest-src 'self';" +
				" frame-src 'self';"
			server = &http.Server{
				ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
				Addr:     "localhost:" + gui.PortEntry.Text,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					scheme := "https://"
					if r.TLS == nil {
						scheme = "http://"
					}
					// Redirect the www subdomain to the bare domain.
					if r.Host == "www."+nbrew.CMSDomain {
						http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
						return
					}
					// Redirect unclean paths to the clean path equivalent.
					if r.Method == "GET" || r.Method == "HEAD" {
						cleanPath := path.Clean(r.URL.Path)
						if cleanPath != "/" {
							_, ok := notebrew.AllowedFileTypes[strings.ToLower(path.Ext(cleanPath))]
							if !ok {
								cleanPath += "/"
							}
						}
						if cleanPath != r.URL.Path {
							cleanURL := *r.URL
							cleanURL.Path = cleanPath
							http.Redirect(w, r, cleanURL.String(), http.StatusMovedPermanently)
							return
						}
					}
					nbrew.AddSecurityHeaders(w)
					r = r.WithContext(context.WithValue(r.Context(), notebrew.LoggerKey, nbrew.Logger.With(
						slog.String("method", r.Method),
						slog.String("url", scheme+r.Host+r.URL.RequestURI()),
					)))
					nbrew.ServeHTTP(w, r)
				}),
			}
			listener, err := net.Listen("tcp", server.Addr)
			if err != nil {
				var errno syscall.Errno
				if !errors.As(err, &errno) {
					dialog.ShowError(err, gui.Window)
					return
				}
				// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
				const WSAEADDRINUSE = syscall.Errno(10048)
				if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
					dialog.ShowError(fmt.Errorf("notebrew is already running on http://"+nbrew.CMSDomain+"/files/"), gui.Window)
					return
				}
				dialog.ShowError(err, gui.Window)
				return
			}
			go func() {
				err := server.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					dialog.ShowError(err, gui.Window)
				}
			}()
			switch runtime.GOOS {
			case "linux":
				exec.Command("xdg-open", "http://localhost:"+gui.PortEntry.Text+"/files/").Start()
			case "windows":
				exec.Command("explorer.exe", "http://localhost:"+gui.PortEntry.Text+"/files/").Start()
			case "darwin":
				exec.Command("open", "http://localhost:"+gui.PortEntry.Text+"/files/").Start()
			}
			gui.StartButton.Disable()
			gui.StopButton.Enable()
			gui.OpenBrowserButton.Enable()
		case <-gui.StopServer:
			if server != nil && nbrew != nil {
				nbrew.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				server.Shutdown(ctx)
			}
			gui.StartButton.Enable()
			gui.StopButton.Disable()
			gui.OpenBrowserButton.Disable()
		}
	}
}

type LogFilter struct {
	Stderr io.Writer
}

func (logFilter *LogFilter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error from ")) {
		return 0, nil
	}
	return logFilter.Stderr.Write(p)
}
