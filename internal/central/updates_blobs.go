package central

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type updateBlobStore struct {
	root      string
	mu        sync.Mutex
	upload    chan struct{}
	downloads chan struct{}
	inspect   func(context.Context, string) (managed.RPMPackage, string, error)
}

func (b *updateBlobStore) admit(id string, size int64) error {
	entries, err := os.ReadDir(filepath.Join(b.root, "sha256"))
	if err != nil {
		return err
	}
	count := 0
	var stored int64
	present := false
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".rpm")
		if !strings.HasSuffix(entry.Name(), ".rpm") || !updateDigestPattern.MatchString(name) {
			return ErrConflict
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o077 != 0 || info.Size() > managed.MaxUpdateArtifactBytes {
			return ErrConflict
		}
		count++
		stored += info.Size()
		if name == id {
			present = true
		}
	}
	if !present {
		count++
		stored += size
	}
	if count > maxUpdateReleases || stored > maxUpdateStorage {
		return ErrConflict
	}
	return nil
}

func newUpdateBlobStore(directory string) (*updateBlobStore, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("update storage requires initialized absolute state directory")
	}
	root := filepath.Join(directory, "update-blobs")
	for _, candidate := range []string{root, filepath.Join(root, "sha256"), filepath.Join(root, "staging")} {
		if err := os.MkdirAll(candidate, 0o700); err != nil {
			return nil, err
		}
		info, err := os.Lstat(candidate)
		if err != nil || !info.IsDir() || info.Mode()&0o077 != 0 {
			return nil, errors.New("update storage must be private directories without links")
		}
	}
	return &updateBlobStore{root: root, upload: make(chan struct{}, 1), downloads: make(chan struct{}, 4), inspect: inspectUpdateRPM}, nil
}

func (b *updateBlobStore) path(id string) (string, error) {
	if !updateDigestPattern.MatchString(id) {
		return "", ErrInvalid
	}
	return filepath.Join(b.root, "sha256", id+".rpm"), nil
}

func (b *updateBlobStore) open(id string, size int64) (*os.File, error) {
	path, err := b.path(id)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o077 != 0 || info.Size() != size {
		return nil, ErrNotFound
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, ErrConflict
	}
	return file, nil
}

func (b *updateBlobStore) stage(ctx context.Context, body io.Reader) (string, string, int64, managed.RPMPackage, string, error) {
	file, err := os.CreateTemp(filepath.Join(b.root, "staging"), "upload-")
	if err != nil {
		return "", "", 0, managed.RPMPackage{}, "", err
	}
	path := file.Name()
	keep := false
	defer func() {
		file.Close()
		if !keep {
			os.Remove(path)
		}
	}()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body, managed.MaxUpdateArtifactBytes+1))
	if err != nil {
		return "", "", 0, managed.RPMPackage{}, "", err
	}
	if size < 1 || size > managed.MaxUpdateArtifactBytes {
		return "", "", 0, managed.RPMPackage{}, "", ErrInvalid
	}
	if err = file.Sync(); err != nil {
		return "", "", 0, managed.RPMPackage{}, "", err
	}
	if err = file.Close(); err != nil {
		return "", "", 0, managed.RPMPackage{}, "", err
	}
	pack, major, err := b.inspect(ctx, path)
	if err != nil {
		return "", "", 0, managed.RPMPackage{}, "", err
	}
	keep = true
	return path, hex.EncodeToString(hash.Sum(nil)), size, pack, major, nil
}

func (b *updateBlobStore) publish(path, id string, size int64) (bool, error) {
	target, err := b.path(id)
	if err != nil {
		return false, err
	}
	if err = os.Link(path, target); errors.Is(err, os.ErrExist) {
		file, err := b.open(id, size)
		if err != nil {
			return false, err
		}
		defer file.Close()
		hash := sha256.New()
		if _, err = io.Copy(hash, file); err != nil {
			return false, err
		}
		if hex.EncodeToString(hash.Sum(nil)) != id {
			return false, ErrConflict
		}
		return false, nil
	} else if err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err == nil {
		defer dir.Close()
		err = dir.Sync()
	}
	if err != nil {
		os.Remove(target)
		return false, fmt.Errorf("update blob sync: %w", err)
	}
	return true, nil
}
