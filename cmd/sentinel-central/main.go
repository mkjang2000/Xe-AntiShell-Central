package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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

func serve(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("state-dir", defaultStateDirectory, "central state directory")
	agentAddress := flags.String("listen", "127.0.0.1:9443", "HTTPS agent listener")
	adminAddress := flags.String("admin-listen", "127.0.0.1:9444", "loopback operator API listener")
	allowPublic := flags.Bool("allow-non-loopback", false, "allow a non-loopback agent listener")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve accepts no positional arguments")
	}
	if !filepath.IsAbs(*directory) {
		return errors.New("state directory must be absolute")
	}
	material, err := central.LoadMaterial(*directory)
	if err != nil {
		return err
	}
	store, err := central.Open(context.Background(), filepath.Join(*directory, "central.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	backend, err := central.NewServer(store, material, logger)
	if err != nil {
		return err
	}
	agentListener, err := central.Listen(*agentAddress, !*allowPublic)
	if err != nil {
		return err
	}
	defer agentListener.Close()
	adminListener, err := central.Listen(*adminAddress, true)
	if err != nil {
		return err
	}
	defer adminListener.Close()
	agentServer := central.HTTPServer(*agentAddress, backend.AgentHandler())
	adminServer := central.HTTPServer(*adminAddress, backend.AdminHandler())
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- agentServer.Serve(tls.NewListener(agentListener, material.TLSConfig())) }()
	go func() { errorsChannel <- adminServer.Serve(adminListener) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("central service started", "agent_https", agentListener.Addr().String(), "operator_api", adminListener.Addr().String())
	var serveError error
	select {
	case <-ctx.Done():
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			serveError = err
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(serveError, agentServer.Shutdown(shutdownContext), adminServer.Shutdown(shutdownContext))
}

func usage(output io.Writer) {
	fmt.Fprintln(output, `Usage: sentinel-central COMMAND

Commands:
  init              Create private CA, server certificate, signing key and operator credential
  enrollment-token  Create a per-agent, expiring single-use enrollment credential file
  serve             Run HTTPS agent API and loopback-only operator API
  version`)
}
