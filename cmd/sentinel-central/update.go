package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/selfupdate"
)

const updateUsage = `Usage: sentinel-central update list | status
       sentinel-central update apply (--tag TAG | --rpm FILE [--manifest FILE]) [--wait=false]
       sentinel-central update bootstrap (--tag TAG | --rpm FILE [--manifest FILE]) --confirm

Apply installs a publisher-verified newer central RPM after backing up central state.
Bootstrap runs the same update locally as root on installations without the updater socket.
List, status and completed jobs are emitted as JSON.`

func updateCentral(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stderr, updateUsage)
		if len(args) == 0 {
			return flag.ErrHelp
		}
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	out := json.NewEncoder(stdout)
	switch args[0] {
	case "list", "status":
		if len(args) != 1 {
			return fmt.Errorf("update %s accepts no arguments", args[0])
		}
		if args[0] == "list" {
			releases, err := selfupdate.ListReleases(ctx)
			if err != nil {
				return err
			}
			return out.Encode(releases)
		}
		s, err := selfupdate.Current(ctx)
		if err != nil {
			return err
		}
		return out.Encode(s)
	case "apply", "bootstrap":
	default:
		return errors.New(updateUsage)
	}
	bootstrap := args[0] == "bootstrap"
	flags := flag.NewFlagSet("update "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	tag := flags.String("tag", "", "official central GitHub release tag")
	rpmPath := flags.String("rpm", "", "local central RPM")
	manifestPath := flags.String("manifest", "", "optional signed manifest for offline verification")
	wait, confirm := true, false
	if bootstrap {
		flags.BoolVar(&confirm, "confirm", false, "stop, back up and upgrade this existing central server")
	} else {
		flags.BoolVar(&wait, "wait", true, "wait for the worker's result")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*tag != "" && (*rpmPath != "" || *manifestPath != "")) || (*tag == "" && *rpmPath == "") {
		return errors.New("choose --tag TAG or --rpm FILE with an optional --manifest FILE")
	}
	if bootstrap && (!confirm || os.Geteuid() != 0) {
		return errors.New("bootstrap requires root and --confirm to back up and upgrade the running central server")
	}
	signed, body, err := updateSource(ctx, *tag, *rpmPath, *manifestPath)
	if err != nil {
		return err
	}
	defer body.Close()
	if bootstrap {
		status, err := selfupdate.Bootstrap(ctx, signed, body)
		if status.State != "" {
			if writeErr := out.Encode(status); writeErr != nil {
				return writeErr
			}
		}
		return err
	}
	s, err := selfupdate.Apply(ctx, signed, body)
	if err != nil {
		return err
	}
	if wait {
		s, err = awaitCentralUpdate(ctx, signed.Manifest.SHA256, s)
	}
	if writeErr := out.Encode(s); writeErr != nil {
		return writeErr
	}
	return err
}

func openUpdateFile(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, errors.New("update inputs must be regular files")
	}
	return f, info, nil
}

func updateSource(ctx context.Context, tag, rpmPath, manifestPath string) (selfupdate.SignedManifest, io.ReadCloser, error) {
	if tag != "" {
		return selfupdate.GithubDownload(ctx, tag)
	}
	var empty selfupdate.SignedManifest
	var signed selfupdate.SignedManifest
	var err error
	if manifestPath == "" {
		signed, err = selfupdate.GithubManifestForRPM(ctx, filepath.Base(rpmPath))
	} else {
		signed, err = readLocalManifest(manifestPath)
	}
	if err != nil {
		return empty, nil, err
	}
	rpm, info, err := openUpdateFile(rpmPath)
	if err != nil {
		return empty, nil, err
	}
	if info.Size() != signed.Manifest.Size {
		rpm.Close()
		return empty, nil, errors.New("RPM size does not match signed manifest")
	}
	return signed, rpm, nil
}

func awaitCentralUpdate(ctx context.Context, digest string, s selfupdate.Status) (selfupdate.Status, error) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var unavailableSince time.Time
	for {
		if s.SHA256 != digest {
			return s, errors.New("another update is now recorded; inspect update status")
		}
		switch s.State {
		case "succeeded":
			return s, nil
		case "failed", "interrupted":
			return s, fmt.Errorf("central update %s: %s", s.State, s.Detail)
		}
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		case <-tick.C:
		}
		next, err := selfupdate.Current(ctx)
		if err != nil {
			if unavailableSince.IsZero() {
				unavailableSince = time.Now()
			}
			if time.Since(unavailableSince) > time.Minute {
				return s, fmt.Errorf("cannot confirm update; check sentinel-central update status: %w", err)
			}
			continue
		}
		unavailableSince = time.Time{}
		s = next
	}
}

func readLocalManifest(manifestPath string) (selfupdate.SignedManifest, error) {
	var empty selfupdate.SignedManifest
	f, info, err := openUpdateFile(manifestPath)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	if info.Size() > selfupdate.MaxManifestBytes {
		return empty, errors.New("manifest is too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, selfupdate.MaxManifestBytes+1))
	if err != nil {
		return empty, err
	}
	return selfupdate.DecodeManifest(b)
}
