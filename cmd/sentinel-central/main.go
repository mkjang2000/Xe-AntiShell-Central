package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/central"
)

const defaultStateDirectory = "/var/lib/xe-antishell-central"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-central:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return flag.ErrHelp
	}
	switch args[0] {
	case "init":
		return initialize(args[1:], stdout, stderr)
	case "enrollment-token":
		return enrollmentToken(args[1:], stdout, stderr)
	case "init-panel":
		return initializePanel(args[1:], stdout, stderr)
	case "capacity":
		return capacity(args[1:], stdout, stderr)
	case "serve":
		return serve(args[1:], stderr)
	case "version":
		if len(args) != 1 {
			return errors.New("version accepts no arguments")
		}
		fmt.Fprintln(stdout, "0.1.0-dev")
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func initialize(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("state-dir", defaultStateDirectory, "private central state directory")
	hosts := flags.String("hosts", "localhost,127.0.0.1,::1", "comma-separated TLS server names or IP addresses")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("init accepts no positional arguments")
	}
	if err := central.Initialize(*directory, strings.Split(*hosts, ",")); err != nil {
		return err
	}
	store, err := central.Open(context.Background(), filepath.Join(*directory, "central.db"))
	if err != nil {
		return err
	}
	if err = store.Close(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Central service initialized.\nCA file: %s\nOperator credential file: %s\nPrivate signing material remains in the state directory.\n", filepath.Join(*directory, "ca.pem"), filepath.Join(*directory, "operator-token"))
	return nil
}

func enrollmentToken(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("enrollment-token", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("state-dir", defaultStateDirectory, "central state directory")
	agent := flags.String("agent-id", "", "target agent identifier")
	output := flags.String("output-file", "", "private output file (must not exist)")
	lifetime := flags.Duration("ttl", time.Hour, "single-use token lifetime, maximum 24h")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("enrollment-token accepts no positional arguments")
	}
	if *output == "" || *agent == "" {
		return errors.New("--agent-id and --output-file are required")
	}
	if _, err := central.LoadMaterial(*directory); err != nil {
		return err
	}
	store, err := central.Open(context.Background(), filepath.Join(*directory, "central.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.CreateEnrollmentToken(context.Background(), *agent, *lifetime, *output); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Single-use enrollment credential created.\nAgent: %s\nCredential file: %s\n", *agent, *output)
	return nil
}

func usage(output io.Writer) {
	fmt.Fprintln(output, `Usage: sentinel-central COMMAND

Commands:
  init              Create private CA, server certificate, signing key and operator credential
  enrollment-token  Create a per-agent, expiring single-use enrollment credential file
  init-panel        Create web administrator credentials and a private initial password file
  capacity          Sample database, delivery and filesystem usage as JSON
  serve             Run agent/operator APIs and the optional management console
  version`)
}
