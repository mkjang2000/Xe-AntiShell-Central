// Command xeas-central-release signs or verifies a Central RPM on the publisher's machine.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/selfupdate"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xeas-central-release sign|verify --rpm FILE [options]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	rpm := fs.String("rpm", "", "central RPM file")
	var path, tag, keyPath string
	switch args[0] {
	case "sign":
		fs.StringVar(&path, "out", "", "new signed manifest file")
		fs.StringVar(&tag, "tag", "", "vVERSION-rRELEASE")
		fs.StringVar(&keyPath, "key", "", "private Ed25519 PKCS8 PEM file")
	case "verify":
		fs.StringVar(&path, "manifest", "", "signed publisher manifest file")
	default:
		return errors.New("expected sign or verify")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *rpm == "" || path == "" || fs.NArg() != 0 {
		return errors.New("RPM and manifest paths are required")
	}
	ctx := context.Background()
	if args[0] == "verify" {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, selfupdate.MaxManifestBytes+1))
		if err != nil {
			return err
		}
		s, err := selfupdate.DecodeManifest(data)
		if err != nil {
			return err
		}
		return selfupdate.VerifyRPM(ctx, *rpm, s)
	}
	if keyPath == "" || tag == "" {
		return errors.New("publisher key and release tag are required")
	}
	m, err := selfupdate.PrepareManifest(ctx, *rpm, tag)
	if err != nil {
		return err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	signed, err := selfupdate.SignManifest(m, key)
	if err != nil {
		return err
	}
	// Do not publish an envelope unusable by released Central installations.
	if err = selfupdate.VerifyManifest(signed); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	err = enc.Encode(signed)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("could not write the signed manifest")
	}
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	bad := errors.New("publisher key must be a private, owned, single-link PKCS8 Ed25519 PEM file")
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, bad
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16<<10 {
		return nil, bad
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, bad
	}
	raw, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	defer clear(raw)
	if err != nil || len(raw) > 16<<10 {
		return nil, bad
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, bad
	}
	defer clear(block.Bytes)
	v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := v.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, bad
	}
	return key, nil
}
