package central

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const updatePreviewDomain = "xe-antishell-central/update-preview/v1\x00"

type updatePreview struct {
	Nonce       string                `json:"nonce"`
	IssuedAt    time.Time             `json:"issued_at"`
	ExpiresAt   time.Time             `json:"expires_at"`
	Request     ConsoleUpdateRequest  `json:"request"`
	ReleaseHash string                `json:"release_hash"`
	Groups      []consolePreviewGroup `json:"groups"`
	Targets     []ConsoleUpdateTarget `json:"targets"`
}

func updateSnapshot(ctx context.Context, tx *sql.Tx, request ConsoleUpdateRequest, now time.Time) (updatePreview, ConsoleUpdateRelease, error) {
	snapshot := updatePreview{}
	if !updateDigestPattern.MatchString(request.ReleaseID) {
		return snapshot, ConsoleUpdateRelease{}, ErrInvalid
	}
	if request.Concurrency == 0 {
		request.Concurrency = 1
	}
	if request.Concurrency < 1 || request.Concurrency > 10 {
		return snapshot, ConsoleUpdateRelease{}, ErrInvalid
	}
	var err error
	request.AgentIDs, err = normalizedIDs(request.AgentIDs, consoleMaxTargets)
	if err != nil {
		return snapshot, ConsoleUpdateRelease{}, err
	}
	request.GroupIDs, err = normalizedIDs(request.GroupIDs, 64)
	if err != nil {
		return snapshot, ConsoleUpdateRelease{}, err
	}
	release, err := loadUpdateRelease(ctx, tx, request.ReleaseID)
	if err != nil {
		return snapshot, release, err
	}
	snapshot.Request = request
	snapshot.ReleaseHash, err = consoleHash(release.UpdateRelease)
	if err != nil {
		return snapshot, release, err
	}
	snapshot.Groups = []consolePreviewGroup{}
	snapshot.Targets = []ConsoleUpdateTarget{}
	selected := map[string]bool{}
	for _, id := range request.AgentIDs {
		selected[id] = true
	}
	for _, id := range request.GroupIDs {
		group, err := loadConsoleGroup(ctx, tx, id)
		if err != nil {
			return snapshot, release, err
		}
		hash, err := consoleHash(group.AgentIDs)
		if err != nil {
			return snapshot, release, err
		}
		snapshot.Groups = append(snapshot.Groups, consolePreviewGroup{ID: id, Version: group.Version, Generation: group.generation, MemberHash: hash})
		for _, agent := range group.AgentIDs {
			selected[agent] = true
		}
	}
	if len(selected) < 1 || len(selected) > consoleMaxTargets {
		return snapshot, release, ErrInvalid
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		target, err := updateTarget(ctx, tx, id, release, now)
		if err != nil {
			return snapshot, release, err
		}
		snapshot.Targets = append(snapshot.Targets, target)
	}
	return snapshot, release, nil
}

func updateTarget(ctx context.Context, tx *sql.Tx, id string, release ConsoleUpdateRelease, now time.Time) (ConsoleUpdateTarget, error) {
	target := ConsoleUpdateTarget{AgentID: id}
	var revoked int
	var body []byte
	var received int64
	var active string
	err := tx.QueryRowContext(ctx, `SELECT a.enrollment_id,a.revoked,i.inventory_json,coalesce(i.received_at_ns,0),coalesce(h.revision,0),coalesce(h.active_job_id,'') FROM agents a LEFT JOIN update_inventory i ON i.agent_id=a.agent_id AND i.enrollment_id=a.enrollment_id LEFT JOIN update_heads h ON h.agent_id=a.agent_id AND h.enrollment_id=a.enrollment_id WHERE a.agent_id=?`, id).Scan(&target.EnrollmentID, &revoked, &body, &received, &target.CurrentRevision, &active)
	if errors.Is(err, sql.ErrNoRows) {
		target.ExcludeReason = "not_found"
		return target, nil
	}
	if err != nil {
		return target, err
	}
	if revoked != 0 {
		target.ExcludeReason = "revoked"
		return target, nil
	}
	if len(body) == 0 {
		target.ExcludeReason = "bootstrap_required"
		return target, nil
	}
	var inventory managed.UpdateInventory
	if err = json.Unmarshal(body, &inventory); err != nil {
		return target, err
	}
	target.CurrentPackage = inventory.InstalledPackage
	target.CurrentPackageHash, _ = consoleHash(inventory.InstalledPackage)
	snapshot := inventory
	snapshot.ObservedAt = time.Time{}
	snapshot.RunningVersion = ""
	target.InventoryHash, _ = consoleHash(snapshot)
	switch {
	case inventory.Validate() != nil || !inventory.Supported:
		target.ExcludeReason = "unsupported"
	case !inventory.Enabled:
		target.ExcludeReason = "disabled"
	case received < now.Add(-24*time.Hour).UnixNano():
		target.ExcludeReason = "inventory_stale"
	case inventory.OSFamily != release.OSFamily || inventory.OSMajor != release.OSMajor || inventory.Arch != release.Package.Arch:
		target.ExcludeReason = "platform_mismatch"
	case active != "":
		target.ExcludeReason = "busy"
	case target.CurrentRevision >= math.MaxInt64:
		target.ExcludeReason = "revision_exhausted"
	case compareUpdatePackage(release.Package, *inventory.InstalledPackage) == 0:
		target.ExcludeReason = "already_current"
	case compareUpdatePackage(release.Package, *inventory.InstalledPackage) < 0:
		target.ExcludeReason = "downgrade"
	default:
		target.Eligible = true
	}
	return target, nil
}

func (s *Server) encodeUpdatePreview(snapshot updatePreview) (string, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	if len(body) > previewMaxBytes {
		return "", ErrInvalid
	}
	signature := ed25519.Sign(s.material.PolicyKey, append([]byte(updatePreviewDomain), body...))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Server) decodeUpdatePreview(token string, now time.Time) (updatePreview, error) {
	var snapshot updatePreview
	if len(token) > base64.RawURLEncoding.EncodedLen(previewMaxBytes)+128 {
		return snapshot, ErrConflict
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return snapshot, ErrConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(body) > previewMaxBytes {
		return snapshot, ErrConflict
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(s.material.PolicyKey.Public().(ed25519.PublicKey), append([]byte(updatePreviewDomain), body...), sig) {
		return snapshot, ErrConflict
	}
	if managed.DecodeStrict(body, previewMaxBytes, &snapshot) != nil || snapshot.Nonce == "" || snapshot.IssuedAt.After(now.Add(time.Minute)) || !now.Before(snapshot.ExpiresAt) || !snapshot.ExpiresAt.After(snapshot.IssuedAt) || snapshot.ExpiresAt.Sub(snapshot.IssuedAt) > previewLifetime {
		return updatePreview{}, ErrConflict
	}
	return snapshot, nil
}

func sameUpdateSnapshot(a, b updatePreview) bool {
	x, _ := consoleHash(struct {
		Request ConsoleUpdateRequest
		Release string
		Groups  []consolePreviewGroup
		Targets []ConsoleUpdateTarget
	}{a.Request, a.ReleaseHash, a.Groups, a.Targets})
	y, _ := consoleHash(struct {
		Request ConsoleUpdateRequest
		Release string
		Groups  []consolePreviewGroup
		Targets []ConsoleUpdateTarget
	}{b.Request, b.ReleaseHash, b.Groups, b.Targets})
	return x == y
}
