package central

import (
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type agentConfigurationRetentionImpact struct {
	CurrentMinutes           int        `json:"current_minutes"`
	ProposedMinutes          int        `json:"proposed_minutes"`
	CurrentCutoff            time.Time  `json:"current_cutoff"`
	ProposedCutoff           time.Time  `json:"proposed_cutoff"`
	OldestObservation        *time.Time `json:"oldest_observation,omitempty"`
	ExistingBacklog          *uint64    `json:"existing_backlog,omitempty"`
	BacklogTruncated         *bool      `json:"backlog_truncated,omitempty"`
	DiskAvailableBytes       *uint64    `json:"disk_available_bytes,omitempty"`
	EstimatedNewlyExpiredMax *uint64    `json:"estimated_newly_expired_max,omitempty"`
}

func observationRetentionDuration(minutes, days int) int {
	if minutes > 0 {
		return minutes
	}
	return days * 24 * 60
}

func estimateAgentRetention(heartbeat managed.Heartbeat, eff managed.AgentConfigurationEffective, set managed.AgentConfigurationSet, inherit []string, now time.Time) *agentConfigurationRetentionImpact {
	current := observationRetentionDuration(eff.ObservationHistoryMinutes, eff.RetentionDays)
	proposed := current
	if set.Retention != nil {
		proposed = set.Retention.ObservationHistoryMinutes
	} else if slices.Contains(inherit, managed.AgentConfigRetentionKey) {
		proposed = observationRetentionDuration(eff.LocalObservationHistoryMinutes, eff.LocalRetentionDays)
	}
	if proposed >= current {
		return nil
	}
	impact := &agentConfigurationRetentionImpact{
		CurrentMinutes: current, ProposedMinutes: proposed,
		CurrentCutoff: now.Add(-time.Duration(current) * time.Minute), ProposedCutoff: now.Add(-time.Duration(proposed) * time.Minute),
	}
	details := heartbeat.Status.CapabilityReport.Capabilities["storage.capacity"].Details
	read := func(key string) *uint64 {
		value, err := strconv.ParseUint(details[key], 10, 64)
		if err != nil {
			return nil
		}
		return &value
	}
	if oldest, err := time.Parse(time.RFC3339Nano, details["oldest_event_at"]); err == nil && !oldest.After(now) {
		at := oldest.UTC()
		impact.OldestObservation = &at
	}
	impact.ExistingBacklog = read("retention_backlog_events")
	if truncated, err := strconv.ParseBool(details["retention_backlog_truncated"]); err == nil {
		impact.BacklogTruncated = &truncated
	}
	impact.DiskAvailableBytes = read("disk_available_bytes")

	// Daily counters are accepted observations, not a deletion count. For a
	// recent bounded window their sum is an upper estimate; older windows or
	// unavailable counters remain unknown. Findings and queued reports are
	// still protected by the agent's sweep.
	today := heartbeat.SentAt.UTC().Truncate(24 * time.Hour)
	from := impact.CurrentCutoff
	if first := impact.OldestObservation; first != nil && first.After(from) {
		from = *first
	}
	if !from.Before(impact.ProposedCutoff) {
		none := uint64(0)
		impact.EstimatedNewlyExpiredMax = &none
	} else if measured, err := time.Parse(time.RFC3339Nano, details["measurement_started_at"]); err == nil &&
		!from.Before(measured) && details["utc_day"] == today.Format(time.DateOnly) && !from.Before(today.AddDate(0, 0, -1)) {
		total := read("stored_events_today")
		if from.Before(today) {
			yesterday := read("stored_events_yesterday")
			if total == nil || yesterday == nil || *total > math.MaxUint64-*yesterday {
				return impact
			}
			*total += *yesterday
		}
		impact.EstimatedNewlyExpiredMax = total
	}
	return impact
}
