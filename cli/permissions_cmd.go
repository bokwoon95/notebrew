package cli

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
)

type PermissionsCmd struct {
	Notebrew *notebrew.Notebrew
	Stdout   io.Writer
	Username sql.NullString
	SiteName sql.NullString
	Grant    bool
	Revoke   bool
	SetOwner bool
	ShowID   bool
}

func PermissionsCommand(nbrew *notebrew.Notebrew, args ...string) (*PermissionsCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd PermissionsCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("user", "", func(s string) error {
		cmd.Username = sql.NullString{String: strings.TrimSpace(s), Valid: true}
		return nil
	})
	flagset.Func("site", "", func(s string) error {
		cmd.SiteName = sql.NullString{String: strings.TrimSpace(s), Valid: true}
		return nil
	})
	flagset.BoolVar(&cmd.Grant, "grant", false, "")
	flagset.BoolVar(&cmd.Revoke, "revoke", false, "")
	flagset.BoolVar(&cmd.SetOwner, "setowner", false, "")
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit
Flags:`)
		flagset.PrintDefaults()
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	flagArgs := flagset.Args()
	if len(flagArgs) > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagArgs, " "))
	}
	if cmd.Grant && cmd.Revoke {
		flagset.Usage()
		return nil, fmt.Errorf("cannot use -grant with -revoke")
	}
	if cmd.SetOwner && cmd.Revoke {
		flagset.Usage()
		return nil, fmt.Errorf("cannot use -setowner with -revoke")
	}
	return &cmd, nil
}

func (cmd *PermissionsCmd) Run() error {
	type Result struct {
		UserID    notebrew.ID
		Username  string
		SiteID    notebrew.ID
		SiteName  string
		OwnerID   notebrew.ID
		OwnerName string
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if !cmd.Username.Valid && !cmd.SiteName.Valid {
		cursor, err := sq.FetchCursor(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "SELECT {*}" +
				" FROM site_user" +
				" RIGHT JOIN users ON users.user_id = site_user.user_id" +
				" RIGHT JOIN site ON site.site_id = site_user.site_id" +
				" LEFT JOIN site_owner ON site_owner.site_id = site.site_id" +
				" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
				" ORDER BY users.user_id, site.site_id",
		}, func(row *sq.Row) permissions {
			return permissions{
				UserID:    row.UUID("users.user_id"),
				Username:  row.String("users.username"),
				SiteID:    row.UUID("site.site_id"),
				SiteName:  row.String("site.site_name"),
				OwnerID:   row.UUID("owner.user_id"),
				OwnerName: row.String("owner.username"),
			}
		})
		if err != nil {
			return err
		}
		defer cursor.Close()
		for cursor.Next() {
			permissions, err := cursor.Result()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.Stdout, permissions.toString(cmd.ShowID))
		}
		return cursor.Close()
	}
	if cmd.Username.Valid {
		exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "SELECT 1 FROM users WHERE username = {username}",
			Values: []any{
				sq.StringParam("username", cmd.Username.String),
			},
		})
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("user %q does not exist", cmd.Username.String)
		}
		if !cmd.SiteName.Valid {
			cursor, err := sq.FetchCursor(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format: "SELECT {*}" +
					" FROM site" +
					" JOIN site_user ON site_user.site_id = site.site_id" +
					" JOIN users ON users.user_id = site_user.user_id" +
					" LEFT JOIN site_owner ON site_owner.site_id = site.site_id" +
					" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
					" WHERE users.username = {username}" +
					" ORDER BY site.site_id",
				Values: []any{
					sq.StringParam("username", cmd.Username.String),
				},
			}, func(row *sq.Row) permissions {
				return permissions{
					UserID:    row.UUID("users.user_id"),
					Username:  row.String("users.username"),
					SiteID:    row.UUID("site.site_id"),
					SiteName:  row.String("site.site_name"),
					OwnerID:   row.UUID("owner.user_id"),
					OwnerName: row.String("owner.username"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			for cursor.Next() {
				permissions, err := cursor.Result()
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.Stdout, permissions.toString(cmd.ShowID))
			}
			return cursor.Close()
		}
	}
	if cmd.SiteName.Valid {
		exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
			Values: []any{
				sq.StringParam("siteName", cmd.SiteName.String),
			},
		})
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("site %q does not exist", cmd.SiteName.String)
		}
		if !cmd.Username.Valid {
			cursor, err := sq.FetchCursor(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format: "SELECT {*}" +
					" FROM users" +
					" JOIN site_user ON site_user.user_id = users.user_id" +
					" JOIN site ON site.site_id = site_user.site_id" +
					" LEFT JOIN site_owner ON site_owner.site_id = site.site_id" +
					" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
					" WHERE site.site_name = {siteName}" +
					" ORDER BY users.user_id",
				Values: []any{
					sq.StringParam("siteName", cmd.SiteName.String),
				},
			}, func(row *sq.Row) permissions {
				return permissions{
					UserID:    row.UUID("users.user_id"),
					Username:  row.String("users.username"),
					SiteID:    row.UUID("site.site_id"),
					SiteName:  row.String("site.site_name"),
					OwnerID:   row.UUID("owner.user_id"),
					OwnerName: row.String("owner.username"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			for cursor.Next() {
				permissions, err := cursor.Result()
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.Stdout, permissions.toString(cmd.ShowID))
			}
			return cursor.Close()
		}
	}
	if !cmd.Grant && !cmd.Revoke && !cmd.SetOwner {
		permissions, err := sq.FetchOne(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "SELECT {*}" +
				" FROM site_user" +
				" JOIN users ON users.user_id = site_user.user_id" +
				" JOIN site ON site.site_id = site_user.site_id" +
				" LEFT JOIN site_owner ON site_owner.site_id = site.site_id" +
				" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
				" WHERE users.username = {username}" +
				" AND site.site_name = {siteName}" +
				" ORDER BY users.user_id, site.site_id",
			Values: []any{
				sq.StringParam("username", cmd.Username.String),
				sq.StringParam("siteName", cmd.SiteName.String),
			},
		}, func(row *sq.Row) permissions {
			return permissions{
				UserID:    row.UUID("users.user_id"),
				Username:  row.String("users.username"),
				SiteID:    row.UUID("site.site_id"),
				SiteName:  row.String("site.site_name"),
				OwnerID:   row.UUID("owner.user_id"),
				OwnerName: row.String("owner.username"),
			}
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				fmt.Fprintln(cmd.Stdout, "no permissions")
				return nil
			}
			return err
		}
		fmt.Fprintln(cmd.Stdout, permissions.toString(cmd.ShowID))
		return nil
	}
	if cmd.Grant {
		result, err := sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "INSERT INTO site_user (site_id, user_id)" +
				" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
			Values: []any{
				sq.StringParam("username", cmd.Username.String),
				sq.StringParam("siteName", cmd.SiteName.String),
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
		}
		if result.RowsAffected == 0 {
			fmt.Fprintln(cmd.Stdout, "user already has permissions for the site")
		} else {
			fmt.Fprintln(cmd.Stdout, "granted permission")
		}
	}
	if cmd.Revoke {
		result, err := sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "DELETE FROM site_user" +
				" WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})" +
				" AND user_id = (SELECT user_id FROM users WHERE username = {username})",
			Values: []any{
				sq.StringParam("username", cmd.Username.String),
				sq.StringParam("siteName", cmd.SiteName.String),
			},
		})
		if err != nil {
			return err
		}
		if result.RowsAffected == 0 {
			fmt.Fprintln(cmd.Stdout, "user has no permissions for the site")
		} else {
			fmt.Fprintln(cmd.Stdout, "permission revoked")
		}
	}
	if cmd.SetOwner {
		switch cmd.Notebrew.Dialect {
		case "sqlite", "postgres":
			_, err := sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format: "INSERT INTO site_owner (site_id, user_id)" +
					" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))" +
					" ON CONFLICT (site_id) DO UPDATE SET user_id = EXCLUDED.user_id",
				Values: []any{
					sq.StringParam("username", cmd.Username.String),
					sq.StringParam("siteName", cmd.SiteName.String),
				},
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.Stdout, "set owner")
		case "mysql":
			_, err := sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format: "INSERT INTO site_owner (site_id, user_id)" +
					" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username})) AS new" +
					" ON DUPLICATE KEY UPDATE user_id = new.user_id",
				Values: []any{
					sq.StringParam("username", cmd.Username.String),
					sq.StringParam("siteName", cmd.SiteName.String),
				},
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.Stdout, "set owner")
		default:
			return fmt.Errorf("unsupported dialect: %s", cmd.Notebrew.Dialect)
		}
	}
	return nil
}

type permissions struct {
	UserID    notebrew.ID
	Username  string
	SiteID    notebrew.ID
	SiteName  string
	OwnerID   notebrew.ID
	OwnerName string
}

func (p permissions) toString(showID bool) string {
	var b strings.Builder
	b.WriteString("user = ")
	if p.UserID.IsZero() {
		b.WriteString("NULL")
	} else {
		b.WriteString(strconv.Quote(p.Username))
		if showID {
			b.WriteString(" (" + p.UserID.String() + ")")
		}
	}
	b.WriteString(", site = ")
	if p.SiteID.IsZero() {
		b.WriteString("NULL")
	} else {
		b.WriteString(strconv.Quote(p.SiteName))
		if showID {
			b.WriteString(" (" + p.SiteID.String() + ")")
		}
	}
	b.WriteString(", owner = ")
	if p.OwnerID.IsZero() {
		b.WriteString("NULL")
	} else {
		b.WriteString(strconv.Quote(p.OwnerName))
		if showID {
			b.WriteString(" (" + p.OwnerID.String() + ")")
		}
	}
	return b.String()
}
