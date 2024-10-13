package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/sync/errgroup"
)

type CreatesiteCmd struct {
	Notebrew        *notebrew.Notebrew
	Stdout          io.Writer
	SiteName        string
	SiteTitle       string
	SiteTagline     string
	SiteDescription string
}

func CreatesiteCommand(nbrew *notebrew.Notebrew, args ...string) (*CreatesiteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd CreatesiteCmd
	var siteNameProvided bool
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("name", "", func(s string) error {
		siteNameProvided = true
		cmd.SiteName = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("title", "", func(s string) error {
		cmd.SiteTitle = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("tagline", "", func(s string) error {
		cmd.SiteTagline = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("description", "", func(s string) error {
		cmd.SiteDescription = strings.TrimSpace(s)
		return nil
	})
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit`)
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	if flagset.NArg() > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagset.Args(), " "))
	}
	if !siteNameProvided {
		fmt.Println("Press Ctrl+C to exit.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Site name: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.SiteName = strings.TrimSpace(text)
			if cmd.SiteName == "" {
				fmt.Println("site name cannot be empty")
				continue
			}
			if slices.Contains(notebrew.ReservedSubdomains, cmd.SiteName) {
				fmt.Println("site name not allowed")
				continue
			}
			for _, char := range cmd.SiteName {
				if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '.' {
					fmt.Println("only lowercase letters, numbers, hyphen and dot allowed in site name")
					continue
				}
			}
			if len(cmd.SiteName) > 30 {
				fmt.Println("cannot exceed 30 characters")
				continue
			}
			existsInDB, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
				Values: []any{
					sq.StringParam("siteName", cmd.SiteName),
				},
			})
			if err != nil {
				return nil, err
			}
			var sitePrefix string
			if strings.Contains(cmd.SiteName, ".") {
				sitePrefix = cmd.SiteName
			} else {
				sitePrefix = "@" + cmd.SiteName
			}
			var existsInFS bool
			_, err = fs.Stat(cmd.Notebrew.FS, sitePrefix)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return nil, err
				}
			} else {
				existsInFS = true
			}
			if existsInDB && existsInFS {
				fmt.Println("site already exists")
				continue
			}
			fmt.Print("Site title: ")
			text, err = reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.SiteTitle = strings.TrimSpace(text)
			fmt.Print("Site tagline: ")
			text, err = reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.SiteTagline = strings.TrimSpace(text)
			fmt.Print("Site description: ")
			text, err = reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.SiteDescription = strings.TrimSpace(text)
			break
		}
	}
	return &cmd, nil
}

func (cmd *CreatesiteCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.SiteName == "" {
		return fmt.Errorf("site name cannot be empty")
	}
	if slices.Contains(notebrew.ReservedSubdomains, cmd.SiteName) {
		return fmt.Errorf("site name not allowed")
	}
	for _, char := range cmd.SiteName {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '.' {
			return fmt.Errorf("only lowercase letters, numbers, hyphen and dot allowed in site name")
		}
	}
	if len(cmd.SiteName) > 30 {
		return fmt.Errorf("site name cannot exceed 30 characters")
	}
	existsInDB, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
		Values: []any{
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	var sitePrefix string
	if strings.Contains(cmd.SiteName, ".") {
		sitePrefix = cmd.SiteName
	} else {
		sitePrefix = "@" + cmd.SiteName
	}
	var existsInFS bool
	_, err = fs.Stat(cmd.Notebrew.FS, sitePrefix)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		existsInFS = true
	}
	if existsInDB && existsInFS {
		return fmt.Errorf("site already exists")
	}
	_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
		Values: []any{
			sq.UUIDParam("siteID", notebrew.NewID()),
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		if cmd.Notebrew.ErrorCode == nil {
			return err
		}
		errorCode := cmd.Notebrew.ErrorCode(err)
		if !notebrew.IsKeyViolation(cmd.Notebrew.Dialect, errorCode) {
			return err
		}
		fmt.Fprintln(cmd.Stdout, "site already exists in the database")
	} else {
		fmt.Fprintln(cmd.Stdout, "created site in the database")
	}
	if existsInFS {
		fmt.Fprintln(cmd.Stdout, "site already exists in the filesystem")
	} else {
		err = cmd.Notebrew.FS.Mkdir(sitePrefix, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
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
			err = cmd.Notebrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		}
		siteGen, err := notebrew.NewSiteGenerator(context.Background(), notebrew.SiteGeneratorConfig{
			FS:                 cmd.Notebrew.FS,
			ContentDomain:      cmd.Notebrew.ContentDomain,
			ContentDomainHTTPS: cmd.Notebrew.ContentDomainHTTPS,
			CDNDomain:          cmd.Notebrew.CDNDomain,
			SitePrefix:         sitePrefix,
		})
		if err != nil {
			return err
		}
		group, groupctx := errgroup.WithContext(context.Background())
		group.Go(func() error {
			siteConfig := notebrew.SiteConfig{
				LanguageCode:   "en",
				Title:          cmd.SiteTitle,
				Tagline:        cmd.SiteTagline,
				Emoji:          "☕️",
				Favicon:        "",
				CodeStyle:      "onedark",
				TimezoneOffset: "+00:00",
				Description:    cmd.SiteDescription,
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
				return err
			}
			writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = io.Copy(writer, bytes.NewReader(b))
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/postlist.json")
			if err != nil {
				return err
			}
			writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/postlist.json"), 0644)
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
		group.Go(func() error {
			b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/index.html")
			if err != nil {
				return err
			}
			writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
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
			creationTime := time.Now()
			err = siteGen.GeneratePage(groupctx, "pages/index.html", string(b), creationTime, creationTime)
			if err != nil {
				return err
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/404.html")
			if err != nil {
				return err
			}
			writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
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
			creationTime := time.Now()
			err = siteGen.GeneratePage(groupctx, "pages/404.html", string(b), creationTime, creationTime)
			if err != nil {
				return err
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/post.html")
			if err != nil {
				return err
			}
			writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/post.html"), 0644)
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
		group.Go(func() error {
			b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/postlist.html")
			if err != nil {
				return err
			}
			writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/postlist.html"), 0644)
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
			tmpl, err := siteGen.PostListTemplate(context.Background(), "")
			if err != nil {
				return err
			}
			_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
			if err != nil {
				return err
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.Stdout, "created site in the filesystem")
	}
	return nil
}
