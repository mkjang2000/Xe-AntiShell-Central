package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/central"
)

func capacity(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("capacity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("state-dir", defaultStateDirectory, "central state directory")
	floor := flags.Uint64("min-free-bytes", 0, "fail when available filesystem bytes fall below this value")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("capacity accepts no positional arguments")
	}
	sample, err := central.SampleStorageCapacity(context.Background(), filepath.Join(*directory, "central.db"))
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(sample); err != nil {
		return err
	}
	if sample.FilesystemAvailableBytes < *floor {
		return fmt.Errorf("available filesystem space %d bytes is below requested minimum %d", sample.FilesystemAvailableBytes, *floor)
	}
	return nil
}
