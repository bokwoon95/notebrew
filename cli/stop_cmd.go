package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/bokwoon95/notebrew"
)

type StopCmd struct {
	Notebrew *notebrew.Notebrew
	Stdout   io.Writer
}

func StopCommand(nbrew *notebrew.Notebrew, configDir string, args ...string) (*StopCmd, error) {
	var cmd StopCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
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

func (cmd *StopCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	pid, name, err := portPID(cmd.Notebrew.Port)
	if err != nil {
		return err
	}
	if pid == 0 {
		fmt.Fprintf(cmd.Stdout, "could not find any process listening on port %d\n", cmd.Notebrew.Port)
		return nil
	}
	if runtime.GOOS == "windows" {
		killCmd := exec.Command("taskkill.exe", "/t", "/f", "/pid", strconv.Itoa(pid))
		err := killCmd.Run()
		if err != nil {
			return err
		}
	} else {
		var pgid int
		cmd := exec.Command("ps", "-o", "pgid=", "-p", strconv.Itoa(pid))
		b, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
				// ps returning 1 is not necessarily an error, because it
				// also returns 1 if no result was found. Return an error only if
				// ps also printed something to stderr.
				return err
			}
			pgid = -pid
		} else {
			ppid, err := strconv.Atoi(string(bytes.TrimSpace(b)))
			if err != nil {
				pgid = -pid
			} else {
				pgid = -ppid
			}
		}
		killCmd := exec.Command("kill", "--", strconv.Itoa(pgid))
		err = killCmd.Run()
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(cmd.Stdout, "stopped %s (pid %d)\n", name, pid)
	return nil
}
