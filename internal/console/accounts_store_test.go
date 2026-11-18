package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAccountDatabaseImportsBootstrapOnlyOnce(t *testing.T) {
	ctx := context.Background()
	seed := testCredentials(t)
	filename := filepath.Join(t.TempDir(), "accounts.db")
	store, err := openAccountStore(filename, seed)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private database: %v %v", info, err)
	}
	credentials, err := GenerateCredentials("replacement", "account-password-fixture1!", seed.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.mutate(ctx, "admin", "created", accountRecord{Account: Account{Username: "replacement", Role: RoleAdmin}, credentials: credentials}, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	admin, err := store.get(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.mutate(ctx, "replacement", "deleted", admin, admin.Version, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openAccountStore(filename, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if _, err = store.get(ctx, "admin"); !errors.Is(err, errAccountMissing) {
		t.Fatal("deleted bootstrap account was recreated")
	}
	replacement, err := store.get(ctx, "replacement")
	if err != nil || replacement.Role != RoleAdmin || !replacement.credentials.Verify("replacement", "account-password-fixture1!") {
		t.Fatal("durable account did not survive reopening")
	}
	link := filepath.Join(t.TempDir(), "link.db")
	if err = os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := openAccountStore(link, seed); err == nil {
		unsafe.db.Close()
		t.Fatal("symlink account database accepted")
	}
	if err = os.Chmod(filename, 0o640); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := openAccountStore(filename, seed); err == nil {
		unsafe.db.Close()
		t.Fatal("shared account database accepted")
	}
}

func TestAccountVersionsRejectDeletedIdentityReplay(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	ctx := context.Background()
	first, _ := accountFixture(t, s, "recreated", RoleViewer)
	if _, err := s.accounts.mutate(ctx, "admin", "deleted", first, first.Version, s.now()); err != nil {
		t.Fatal(err)
	}
	second, _ := accountFixture(t, s, "recreated", RoleViewer)
	if second.Version <= first.Version {
		t.Fatal("account recreation reused an old version")
	}
	if _, err := s.accounts.mutate(ctx, "admin", "deleted", first, first.Version, s.now()); !errors.Is(err, errAccountConflict) {
		t.Fatalf("stale deletion: %v", err)
	}
}

func TestConcurrentAccountChangesPreserveOneAdministrator(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	second, _ := accountFixture(t, s, "second", RoleAdmin)
	first, err := s.accounts.get(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, record := range []accountRecord{first, second} {
		wait.Add(1)
		go func(record accountRecord) {
			defer wait.Done()
			record.Role = RoleViewer
			_, err := s.accounts.mutate(context.Background(), "admin", "role_changed", record, record.Version, s.now())
			results <- err
		}(record)
	}
	wait.Wait()
	close(results)
	allowed, protected := 0, 0
	for err := range results {
		if err == nil {
			allowed++
		} else if errors.Is(err, errLastAdmin) {
			protected++
		} else {
			t.Fatal(err)
		}
	}
	if allowed != 1 || protected != 1 {
		t.Fatalf("administrator race: allowed=%d protected=%d", allowed, protected)
	}
}
