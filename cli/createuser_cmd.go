package cli

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type CreateuserCmd struct {
	Notebrew     *notebrew.Notebrew
	Stdout       io.Writer
	Username     string
	Email        string
	PasswordHash string
	SiteLimit    sql.NullInt64
	StorageLimit sql.NullInt64
	UserFlags    sql.NullString
}

func CreateuserCommand(nbrew *notebrew.Notebrew, args ...string) (*CreateuserCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd CreateuserCmd
	cmd.Notebrew = nbrew
	var usernameProvided, emailProvided, passwordHashProvided bool
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("username", "", func(s string) error {
		usernameProvided = true
		cmd.Username = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("email", "", func(s string) error {
		emailProvided = true
		cmd.Email = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("password-hash", "", func(s string) error {
		passwordHashProvided = true
		cmd.PasswordHash = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("site-limit", "", func(s string) error {
		siteLimit, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a valid integer", s)
		}
		cmd.SiteLimit = sql.NullInt64{Int64: siteLimit, Valid: true}
		return nil
	})
	flagset.Func("storage-limit", "", func(s string) error {
		storageLimit, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a valid integer", s)
		}
		cmd.StorageLimit = sql.NullInt64{Int64: storageLimit, Valid: true}
		return nil
	})
	flagset.Func("user-flags", "", func(s string) error {
		cmd.UserFlags = sql.NullString{String: s, Valid: true}
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
	if flagset.NArg() > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagset.Args(), " "))
	}
	if usernameProvided && emailProvided && passwordHashProvided {
		return &cmd, nil
	}
	fmt.Println("Press Ctrl+C to exit.")
	reader := bufio.NewReader(os.Stdin)
	if !usernameProvided {
		for {
			fmt.Print("Username (leave blank for the default user): ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.Username = strings.TrimSpace(text)
			var hasInvalidChar bool
			for _, char := range cmd.Username {
				if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
					hasInvalidChar = true
					break
				}
			}
			if hasInvalidChar {
				fmt.Println("username can only contain lowercase letters, numbers and hyphen")
				continue
			}
			if len(cmd.Username) > 30 {
				fmt.Println("username cannot exceed 30 characters")
				continue
			}
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
			if exists {
				fmt.Println("username already used by an existing user account")
				continue
			}
			break
		}
	}
	if !emailProvided {
		for {
			fmt.Print("Email: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.Email = strings.TrimSpace(text)
			if cmd.Email == "" {
				fmt.Println("email cannot be empty")
				continue
			}
			_, err = mail.ParseAddress(cmd.Email)
			if err != nil {
				fmt.Println("invalid email address")
				continue
			}
			exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", cmd.Email),
				},
			})
			if err != nil {
				return nil, err
			}
			if exists {
				fmt.Println("email already used by an existing user account")
				continue
			}
			break
		}
	}
	if !passwordHashProvided {
		for {
			fmt.Print("Password (will be hidden from view): ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
			}
			if utf8.RuneCount(password) < 8 {
				fmt.Println("password must be at least 8 characters")
				continue
			}
			commonPasswords, err := getCommonPasswords()
			if err != nil {
				return nil, err
			}
			if _, ok := commonPasswords[string(password)]; ok {
				fmt.Println("password is too common")
				continue
			}
			fmt.Print("Confirm password (will be hidden from view): ")
			confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(password, confirmPassword) {
				fmt.Println("passwords do not match")
				continue
			}
			b, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			cmd.PasswordHash = string(b)
			break
		}
	}
	return &cmd, nil
}

func (cmd *CreateuserCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	for _, char := range cmd.Username {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return fmt.Errorf("username can only contain lowercase letters, numbers and hyphen")
		}
	}
	if len(cmd.Username) > 30 {
		return fmt.Errorf("username cannot exceed 30 characters")
	}
	usernameExists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "SELECT 1 FROM users WHERE username = {username}",
		Values: []any{
			sq.StringParam("username", cmd.Username),
		},
	})
	if err != nil {
		return err
	}
	if usernameExists {
		return fmt.Errorf("username already used by an existing user account")
	}
	if cmd.Email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	_, err = mail.ParseAddress(cmd.Email)
	if err != nil {
		return fmt.Errorf("invalid email address")
	}
	emailExists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "SELECT 1 FROM users WHERE email = {email}",
		Values: []any{
			sq.StringParam("email", cmd.Email),
		},
	})
	if err != nil {
		return err
	}
	if emailExists {
		return fmt.Errorf("email already used by an existing user account")
	}
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "INSERT INTO users (user_id, username, email, password_hash, site_limit, storage_limit, user_flags)" +
			" VALUES ({userID}, {username}, {email}, {passwordHash}, {siteLimit}, {storageLimit}, {userFlags})",
		Values: []any{
			sq.UUIDParam("userID", notebrew.NewID()),
			sq.StringParam("username", cmd.Username),
			sq.StringParam("email", cmd.Email),
			sq.StringParam("passwordHash", cmd.PasswordHash),
			sq.Param("siteLimit", cmd.SiteLimit),
			sq.Param("storageLimit", cmd.StorageLimit),
			sq.Param("userFlags", cmd.UserFlags),
		},
	})
	if err != nil {
		return err
	}
	if cmd.Username == "" {
		_, err = sq.Exec(context.Background(), tx, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "INSERT INTO site_user (site_id, user_id)" +
				" VALUES ((SELECT site_id FROM site WHERE site_name = ''), (SELECT user_id FROM users WHERE username = ''))",
		})
		if err != nil {
			return err
		}
		_, err = sq.Exec(context.Background(), tx, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "INSERT INTO site_owner (site_id, user_id)" +
				" VALUES ((SELECT site_id FROM site WHERE site_name = ''), (SELECT user_id FROM users WHERE username = ''))",
		})
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.Stdout, "created user")
	return nil
}

var getCommonPasswords = sync.OnceValues(func() (map[string]struct{}, error) {
	commonPasswords := make(map[string]struct{}, 10000)
	file, err := notebrew.RuntimeFS.Open("embed/top_10000_passwords.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		commonPasswords[string(line)] = struct{}{}
	}
	return commonPasswords, nil
})
