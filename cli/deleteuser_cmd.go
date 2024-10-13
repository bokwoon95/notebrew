package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
)

type DeleteuserCmd struct {
	Notebrew *notebrew.Notebrew
	Stdout   io.Writer
	Username string
}

func DeleteuserCommand(nbrew *notebrew.Notebrew, args ...string) (*DeleteuserCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd DeleteuserCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit
Flags:`)
		flagset.PrintDefaults()
	}
	var usernameProvided bool
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		usernameProvided = true
		cmd.Username = strings.TrimSpace(args[0])
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
	if usernameProvided {
		exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "SELECT 1 FROM users WHERE username = {username}",
			Values: []any{
				sq.StringParam("username", cmd.Username),
			},
		})
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("user does not exist")
		}
	} else {
		fmt.Println("Press Ctrl+C to exit.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Username (leave blank for the default user): ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.Username = strings.TrimSpace(text)
			exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE username = {username}",
				Values: []any{
					sq.StringParam("username", cmd.Username),
				},
			})
			if err != nil {
				return nil, err
			}
			if !exists {
				fmt.Println("user does not exist")
				continue
			}
			break
		}
	}
	return &cmd, nil
}

func (cmd *DeleteuserCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "DELETE FROM site_owner WHERE EXISTS (" +
			" SELECT 1 FROM users WHERE users.user_id = site_owner.user_id AND users.username = {username}" +
			")",
		Values: []any{
			sq.StringParam("username", cmd.Username),
		},
	})
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "DELETE FROM site_user WHERE EXISTS (" +
			" SELECT 1 FROM users WHERE users.user_id = site_user.user_id AND users.username = {username}" +
			")",
		Values: []any{
			sq.StringParam("username", cmd.Username),
		},
	})
	result, err := sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "DELETE FROM users WHERE username = {username}",
		Values: []any{
			sq.StringParam("username", cmd.Username),
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
		fmt.Fprintln(cmd.Stdout, "user does not exist")
	} else {
		fmt.Fprintln(cmd.Stdout, "deleted user")
	}
	return nil
}
