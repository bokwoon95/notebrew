package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/notebrew"
)

type StartCmd struct {
	Notebrew  *notebrew.Notebrew
	Stdout    io.Writer
	ConfigDir string
	Handler   http.Handler
}

func StartCommand(nbrew *notebrew.Notebrew, configDir string, args ...string) (*StartCmd, error) {
	var cmd StartCmd
	cmd.Notebrew = nbrew
	cmd.ConfigDir = configDir
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

func (cmd *StartCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Handler == nil {
		cmd.Handler = cmd.Notebrew
	}
	server, err := NewServer(cmd.Notebrew)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
		const WSAEADDRINUSE = syscall.Errno(10048)
		if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
			if !cmd.Notebrew.CMSDomainHTTPS {
				fmt.Fprintln(cmd.Stdout, "notebrew is already running on http://"+cmd.Notebrew.CMSDomain+"/files/")
			} else {
				fmt.Fprintln(cmd.Stdout, "notebrew is already running (run `notebrew stop` to stop the process)")
			}
			return nil
		}
		return err
	}
	// Swallow SIGHUP so that we can keep running even when the (SSH)
	// session ends (the user should use `notebrew stop` to stop the
	// process).
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for {
			<-ch
		}
	}()
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM)
	if server.Addr == ":443" {
		go http.ListenAndServe(":80", http.HandlerFunc(cmd.Notebrew.RedirectToHTTPS))
		go func() {
			err := server.ServeTLS(listener, "", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Println(err)
				close(wait)
			}
		}()
		fmt.Printf("notebrew is running on %s\n", server.Addr)
	} else {
		go func() {
			err := server.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Println(err)
				close(wait)
			}
		}()
		if !cmd.Notebrew.CMSDomainHTTPS {
			fmt.Printf("notebrew is running on %s\n", "http://"+cmd.Notebrew.CMSDomain+"/files/")
		} else {
			fmt.Printf("notebrew is running on %s\n", server.Addr)
		}
	}
	<-wait
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server.Shutdown(ctx)
	return nil
}
