package cli

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
	"golang.org/x/crypto/blake2b"
)

type CreateinviteCmd struct {
	Notebrew     *notebrew.Notebrew
	Stdout       io.Writer
	Email        sql.NullString
	SiteLimit    sql.NullInt64
	StorageLimit sql.NullInt64
	UserFlags    sql.NullString
}

func CreateinviteCommand(nbrew *notebrew.Notebrew, args ...string) (*CreateinviteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite` and try again")
	}
	var cmd CreateinviteCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("email", "", func(s string) error {
		_, err := mail.ParseAddress(s)
		if err != nil {
			return fmt.Errorf("%q is not a valid email address", s)
		}
		cmd.Email = sql.NullString{String: s, Valid: true}
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
	return &cmd, nil
}

func (cmd *CreateinviteCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	scheme := "https://"
	if !cmd.Notebrew.CMSDomainHTTPS {
		scheme = "http://"
	}
	var inviteTokenBytes [8 + 16]byte
	binary.BigEndian.PutUint64(inviteTokenBytes[:8], uint64(time.Now().Unix()))
	_, err := rand.Read(inviteTokenBytes[8:])
	if err != nil {
		return err
	}
	checksum := blake2b.Sum256(inviteTokenBytes[8:])
	var inviteTokenHash [8 + blake2b.Size256]byte
	copy(inviteTokenHash[:8], inviteTokenBytes[:8])
	copy(inviteTokenHash[8:], checksum[:])
	_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "INSERT INTO invite (invite_token_hash, email, site_limit, storage_limit, user_flags)" +
			" VALUES ({inviteTokenHash}, {email}, {siteLimit}, {storageLimit}, {userFlags})",
		Values: []any{
			sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			sq.Param("email", cmd.Email),
			sq.Param("siteLimit", cmd.SiteLimit),
			sq.Param("storageLimit", cmd.StorageLimit),
			sq.Param("userFlags", cmd.UserFlags),
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.Stdout, scheme+cmd.Notebrew.CMSDomain+"/users/invite/?token="+strings.TrimLeft(hex.EncodeToString(inviteTokenBytes[:]), "0"))
	return nil
}
