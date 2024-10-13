package cli

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type HashpasswordCmd struct {
	Password []byte
	Stdout   io.Writer
}

func HashpasswordCommand(args ...string) (*HashpasswordCmd, error) {
	var cmd HashpasswordCmd
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit`)
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	args = flagset.Args()
	if len(args) > 1 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(args[1:], " "))
	}
	if len(args) == 1 {
		cmd.Password = []byte(args[0])
		return &cmd, nil
	}
	fileinfo, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if (fileinfo.Mode() & os.ModeCharDevice) == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		cmd.Password = b
		return &cmd, nil
	}
	fmt.Fprintln(os.Stderr, "Press Ctrl+C to exit.")
	for {
		fmt.Fprint(os.Stderr, "Password (will be hidden from view): ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if utf8.RuneCount(password) < 8 {
			fmt.Println("password must be at least 8 characters")
			continue
		}
		fmt.Fprint(os.Stderr, "Confirm password (will be hidden from view): ")
		confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(password, confirmPassword) != 1 {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			continue
		}
		cmd.Password = password
		break
	}
	return &cmd, nil
}

func (cmd *HashpasswordCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	passwordHash, err := bcrypt.GenerateFromPassword(cmd.Password, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.Stdout, string(passwordHash))
	return nil
}
