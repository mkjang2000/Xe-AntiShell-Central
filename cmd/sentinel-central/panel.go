package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/central"
	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

// initializePanel is deliberately separate from PKI initialization and never
// resets existing credentials, enrolled agents, signing keys or policies.
func initializePanel(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init-panel", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("state-dir", defaultStateDirectory, "existing central state directory")
	username := flags.String("username", "admin", "web administrator username")
	passwordFile := flags.String("password-file", "", "new private initial password file; default STATE/panel-initial-password")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("init-panel accepts no positional arguments")
	}
	if _, err := central.LoadMaterial(*directory); err != nil {
		return err
	}
	authPath := filepath.Join(*directory, "panel-auth.json")
	if _, err := os.Lstat(authPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("panel credentials already exist or cannot be checked")
	}
	if *passwordFile == "" {
		*passwordFile = filepath.Join(*directory, "panel-initial-password")
	}
	password, err := console.GeneratePassword()
	if err != nil {
		return err
	}
	credentials, err := console.GenerateCredentials(*username, password, console.DefaultArgon2Parameters())
	if err != nil {
		return err
	}
	if err = console.WriteInitialPassword(*passwordFile, password); err != nil {
		return err
	}
	if err = console.WriteCredentials(authPath, credentials); err != nil {
		_ = os.Remove(*passwordFile)
		return err
	}
	fmt.Fprintf(stdout, "Web administrator created.\nUsername: %s\nInitial password file: %s\nRestart central to enable the console.\n", *username, *passwordFile)
	return nil
}
