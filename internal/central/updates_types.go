package central

import (
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const updatePlanTTL = 15 * time.Minute
const updateClaimTTL = 2 * time.Minute
const updateQueueTTL = 7 * 24 * time.Hour
const updateInstallTimeout = 10 * time.Minute

type ConsoleUpdateRelease struct {
	managed.UpdateRelease
	UploadedBy        string `json:"uploaded_by"`
	PublisherVerified bool   `json:"publisher_verified"`
}

type ConsoleUpdateAgent struct {
	AgentID      string                   `json:"agent_id"`
	EnrollmentID string                   `json:"enrollment_id"`
	Hostname     string                   `json:"hostname"`
	Inventory    *managed.UpdateInventory `json:"inventory"`
	ReceivedAt   *time.Time               `json:"received_at"`
	ActiveJobID  string                   `json:"active_job_id"`
}

type ConsoleUpdateRequest struct {
	ReleaseID   string   `json:"release_id"`
	AgentIDs    []string `json:"agent_ids"`
	GroupIDs    []string `json:"group_ids"`
	Concurrency int      `json:"concurrency"`
}

type ConsoleUpdateTarget struct {
	AgentID            string              `json:"agent_id"`
	EnrollmentID       string              `json:"enrollment_id"`
	CurrentPackage     *managed.RPMPackage `json:"current_package"`
	CurrentPackageHash string              `json:"current_package_hash"`
	InventoryHash      string              `json:"inventory_hash"`
	CurrentRevision    uint64              `json:"current_revision"`
	Eligible           bool                `json:"eligible"`
	ExcludeReason      string              `json:"exclude_reason"`
}

type ConsoleUpdateJob struct {
	ID                  string              `json:"id"`
	RolloutID           string              `json:"rollout_id"`
	AgentID             string              `json:"agent_id"`
	EnrollmentID        string              `json:"enrollment_id"`
	Revision            uint64              `json:"revision"`
	State               string              `json:"state"`
	Terminal            bool                `json:"terminal"`
	CurrentPackage      managed.RPMPackage  `json:"current_package"`
	TargetPackage       managed.RPMPackage  `json:"target_package"`
	ObservedPackage     *managed.RPMPackage `json:"observed_package"`
	LastReportAt        *time.Time          `json:"last_report_at"`
	ErrorCode           string              `json:"error_code"`
	StoppedAfterFailure bool                `json:"stopped_after_failure"`
	LateReport          bool                `json:"late_report"`
	CollectionCheck     string              `json:"collection_check"`
	ExpiresAt           time.Time           `json:"expires_at"`
}

type ConsoleUpdateRollout struct {
	ID          string         `json:"id"`
	ReleaseID   string         `json:"release_id"`
	CreatedBy   string         `json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Concurrency int            `json:"concurrency"`
	Cancelled   bool           `json:"cancelled"`
	Paused      bool           `json:"paused"`
	StopReason  string         `json:"stop_reason"`
	Counters    map[string]int `json:"counters"`
}

func updateTerminal(state string) bool {
	switch state {
	case "succeeded", "failed", "expired", "cancelled":
		return true
	}
	return false
}
