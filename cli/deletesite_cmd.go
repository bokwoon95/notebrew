package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
)

type DeletesiteCmd struct {
	Notebrew *notebrew.Notebrew
	Stdout   io.Writer
	SiteName string
}

func DeletesiteCommand(nbrew *notebrew.Notebrew, args ...string) (*DeletesiteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd DeletesiteCmd
	cmd.Notebrew = nbrew
	var confirm bool
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.BoolVar(&confirm, "confirm", false, "")
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit
Flags:`)
		flagset.PrintDefaults()
	}
	var siteNameProvided bool
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		siteNameProvided = true
		cmd.SiteName = strings.TrimSpace(args[0])
		args = args[1:]
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	if flagset.NArg() > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagset.Args(), " "))
	}
	if siteNameProvided {
		if cmd.SiteName == "" {
			return nil, fmt.Errorf("site name cannot be empty")
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
		if !existsInDB && !existsInFS {
			return nil, fmt.Errorf("site does not exist")
		}
		if !confirm {
			fmt.Println("Press Ctrl+C to exit.")
			reader := bufio.NewReader(os.Stdin)
			for {
				fmt.Printf("Are you sure you wish to delete site %q? This action is permanent and cannot be undone. All files within the site will be deleted.\n", cmd.SiteName)
				fmt.Printf("Please confirm the site name that you wish to delete (%s): ", cmd.SiteName)
				text, err := reader.ReadString('\n')
				if err != nil {
					return nil, err
				}
				text = strings.TrimSpace(text)
				if text != cmd.SiteName {
					fmt.Println("site name does not match")
					continue
				}
				break
			}
		}
	} else {
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
			if !existsInDB && !existsInFS {
				fmt.Println("site does not exist")
				continue
			}
			break
		}
		if !confirm {
			for {
				fmt.Printf("Are you sure you wish to delete site %q? This action is permanent and cannot be undone. All files within the site will be deleted.\n", cmd.SiteName)
				fmt.Printf("Please confirm the site name that you wish to delete (%s): ", cmd.SiteName)
				text, err := reader.ReadString('\n')
				if err != nil {
					return nil, err
				}
				text = strings.TrimSpace(text)
				if text != cmd.SiteName {
					fmt.Println("site name does not match")
					continue
				}
				break
			}
		}
	}
	return &cmd, nil
}

func (cmd *DeletesiteCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.SiteName == "" {
		return fmt.Errorf("site name cannot be empty")
	}
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "DELETE FROM site_owner WHERE EXISTS (" +
			"SELECT 1 FROM site WHERE site.site_id = site_owner.site_id AND site.site_name = {siteName}" +
			")",
		Values: []any{
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "DELETE FROM site_user WHERE EXISTS (" +
			"SELECT 1 FROM site WHERE site.site_id = site_user.site_id AND site.site_name = {siteName}" +
			")",
		Values: []any{
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	result, err := sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "DELETE FROM site WHERE site_name = {siteName}",
		Values: []any{
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	if result.RowsAffected == 0 {
		fmt.Fprintln(cmd.Stdout, "site does not exist in the database")
	} else {
		fmt.Fprintln(cmd.Stdout, "deleted site from the database")
	}
	var sitePrefix string
	if strings.Contains(cmd.SiteName, ".") {
		sitePrefix = cmd.SiteName
	} else {
		sitePrefix = "@" + cmd.SiteName
	}
	_, err = fs.Stat(cmd.Notebrew.FS, sitePrefix)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		fmt.Fprintln(cmd.Stdout, "site does not exist in the filesystem")
	} else {
		err = cmd.Notebrew.FS.RemoveAll(sitePrefix)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.Stdout, "deleted site from the filesystem")
	}
	return nil
}
