package cli

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/crypto/blake2b"
)

type DeleteinviteCmd struct {
	Notebrew *notebrew.Notebrew
	Stdout   io.Writer
	Before   sql.NullTime
	After    sql.NullTime
}

func DeleteinviteCommand(nbrew *notebrew.Notebrew, args ...string) (*DeleteinviteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd DeleteinviteCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("before", "", func(s string) error {
		before, err := parseTime(s)
		if err != nil {
			return err
		}
		cmd.Before = before
		return nil
	})
	flagset.Func("after", "", func(s string) error {
		after, err := parseTime(s)
		if err != nil {
			return err
		}
		cmd.After = after
		return nil
	})
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
	if !cmd.Before.Valid && !cmd.After.Valid {
		fmt.Println("Press Ctrl+C to exit.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Delete all invites? (y/n): ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			text = strings.TrimSpace(text)
			if text == "y" {
				break
			}
			if text == "n" {
				fmt.Println("cancelled")
				return nil, flag.ErrHelp
			}
		}
	}
	return &cmd, nil
}

func (cmd *DeleteinviteCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	var exprs []string
	var args []any
	if cmd.Before.Valid {
		inviteTokenHash := make([]byte, 8+blake2b.Size256)
		binary.BigEndian.PutUint64(inviteTokenHash[:8], uint64(cmd.Before.Time.Unix()))
		exprs = append(exprs, "invite_token_hash < {}")
		args = append(args, inviteTokenHash)
	}
	if cmd.After.Valid {
		inviteTokenHash := make([]byte, 8+blake2b.Size256)
		binary.BigEndian.PutUint64(inviteTokenHash[:8], uint64(cmd.Before.Time.Unix()))
		exprs = append(exprs, "invite_token_hash > {}")
		args = append(args, inviteTokenHash)
	}
	condition := sq.Expr("1 = 1")
	if len(exprs) > 0 {
		condition = sq.Expr(strings.Join(exprs, " AND "), args...)
	}
	result, err := sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "DELETE FROM invite WHERE {condition}",
		Values: []any{
			sq.Param("condition", condition),
		},
	})
	if err != nil {
		return err
	}
	if result.RowsAffected == 1 {
		fmt.Fprintln(cmd.Stdout, "1 invite deleted")
	} else {
		fmt.Fprintln(cmd.Stdout, strconv.FormatInt(result.RowsAffected, 10)+" invites deleted")
	}
	return nil
}

func parseTime(s string) (sql.NullTime, error) {
	if s == "" {
		return sql.NullTime{}, nil
	}
	if s == "now" {
		return sql.NullTime{Time: time.Now(), Valid: true}, nil
	}
	s = strings.TrimSuffix(s, "Z")
	for _, format := range []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02T15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04",
		"2006-01-02",
	} {
		if t, err := time.ParseInLocation(format, s, time.UTC); err == nil {
			return sql.NullTime{Time: t, Valid: true}, nil
		}
	}
	return sql.NullTime{}, fmt.Errorf("not a valid time string")
}
