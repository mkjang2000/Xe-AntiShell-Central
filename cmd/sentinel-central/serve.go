package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/central"
	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

func serve(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("state-dir", defaultStateDirectory, "central state directory")
	agentAddress := flags.String("listen", "127.0.0.1:9443", "HTTPS agent listener")
	adminAddress := flags.String("admin-listen", "127.0.0.1:9444", "loopback operator API listener")
	allowPublic := flags.Bool("allow-non-loopback", false, "allow a non-loopback agent listener")
	panelAddress := flags.String("panel-listen", "127.0.0.1:9089", "console listener; empty disables; requires initialized panel credentials")
	allowPublicPanel := flags.Bool("allow-non-loopback-panel", false, "allow a non-loopback console listener")
	panelCert := flags.String("panel-tls-cert", "", "optional PEM TLS certificate for the console")
	panelKey := flags.String("panel-tls-key", "", "optional PEM TLS private key for the console")
	panelPublicOrigin := flags.String("panel-public-origin", "", "external HTTPS console origin behind a trusted TLS-terminating proxy")
	panelTrustedProxies := flags.String("panel-trusted-proxies", "127.0.0.1/32,::1/128", "comma-separated actual proxy peer CIDRs; requires --panel-public-origin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*directory) {
		return errors.New("serve requires an absolute state directory and no positional arguments")
	}
	if (*panelCert == "") != (*panelKey == "") {
		return errors.New("console TLS certificate and key must be provided together")
	}
	options := console.Options{}
	if *panelPublicOrigin != "" {
		options.PublicOrigin = *panelPublicOrigin
		options.TrustedProxies = strings.Split(*panelTrustedProxies, ",")
	} else {
		var explicitProxies bool
		flags.Visit(func(f *flag.Flag) { explicitProxies = explicitProxies || f.Name == "panel-trusted-proxies" })
		if explicitProxies {
			return errors.New("--panel-trusted-proxies requires --panel-public-origin")
		}
	}
	if err := options.Validate(); err != nil {
		return err
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
	var servers []*http.Server
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	add := func(address string, local bool, handler http.Handler, config *tls.Config) error {
		listener, err := central.Listen(address, local)
		if err != nil {
			return err
		}
		if config != nil {
			listener = tls.NewListener(listener, config)
		}
		listeners = append(listeners, listener)
		servers = append(servers, central.HTTPServer(address, handler))
		return nil
	}
	if err = add(*agentAddress, !*allowPublic, backend.AgentHandler(), material.TLSConfig()); err != nil {
		return err
	}
	if err = add(*adminAddress, true, backend.AdminHandler(), nil); err != nil {
		return err
	}
	if *panelAddress != "" {
		authPath := filepath.Join(*directory, "panel-auth.json")
		credentials, loadErr := console.LoadCredentials(authPath)
		if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		}
		if loadErr == nil {
			handler, err := console.NewWithOptions(credentials, backend.ConsoleHandler(), logger, options)
			if err != nil {
				return err
			}
			var config *tls.Config
			if *panelCert != "" {
				certificate, err := tls.LoadX509KeyPair(*panelCert, *panelKey)
				if err != nil {
					return err
				}
				config = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
			}
			if err = add(*panelAddress, !*allowPublicPanel, handler, config); err != nil {
				return err
			}
			logger.Info("central management console enabled", "address", *panelAddress, "tls", config != nil)
		}
	}
	errorsChannel := make(chan error, len(servers))
	for index, server := range servers {
		go func(server *http.Server, listener net.Listener) { errorsChannel <- server.Serve(listener) }(server, listeners[index])
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("central service started", "agent_https", *agentAddress, "operator_api", *adminAddress)
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
	for _, server := range servers {
		serveError = errors.Join(serveError, server.Shutdown(shutdownContext))
	}
	return serveError
}
