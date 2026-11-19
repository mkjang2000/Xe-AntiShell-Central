package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type ApplicationBinding struct {
	Service       string `json:"service"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint64 `json:"policy_version"`
}

// Resolve bindings in the same transaction as the optimistic template save. A
// previously saved pin is independent of the current source, even after deletion.
func resolveTemplateApplications(ctx context.Context, tx *sql.Tx, template *ConsoleTemplate) error {
	settings := &template.Settings
	// Application snapshots are server output. Never sign a caller-supplied body.
	settings.Applications = nil
	if len(settings.ApplicationBindings) == 0 && (template.Version == 0 || settings.ApplicationBindings != nil) {
		return nil
	}
	if len(settings.ApplicationBindings) > managed.MaxApplicationPolicies {
		return fmt.Errorf("%w: 서비스별 정책은 최대 64개입니다", ErrInvalid)
	}
	pinned := make(map[ApplicationBinding]managed.ApplicationPolicy)
	if template.Version != 0 {
		stored, err := loadConsoleTemplate(ctx, tx, template.ID)
		if errors.Is(err, ErrNotFound) || err == nil && stored.Version != template.Version {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if settings.ApplicationBindings == nil {
			// Older editors cannot express this field. An explicit [] clears it.
			settings.ApplicationBindings = stored.Settings.ApplicationBindings
			settings.Applications = stored.Settings.Applications
			return nil
		}
		for _, app := range stored.Settings.Applications {
			pinned[ApplicationBinding{app.Service, app.PolicyID, app.PolicyVersion}] = app
		}
	}
	sources := make(map[string]ConsoleTemplate)
	seen := make(map[string]bool)
	for _, ref := range settings.ApplicationBindings {
		if !managed.ValidApplicationService(ref.Service) || seen[ref.Service] || !identifierPattern.MatchString(ref.PolicyID) || ref.PolicyID == template.ID || ref.PolicyVersion == 0 || ref.PolicyVersion > math.MaxInt64 {
			return fmt.Errorf("%w: 서비스 중복, 정책 ID 또는 참조 버전을 확인하세요", ErrInvalid)
		}
		seen[ref.Service] = true
		if app, ok := pinned[ref]; ok {
			settings.Applications = append(settings.Applications, app)
			continue
		}
		source, ok := sources[ref.PolicyID]
		if !ok {
			var err error
			source, err = loadConsoleTemplate(ctx, tx, ref.PolicyID)
			if errors.Is(err, ErrNotFound) {
				return ErrConflict
			}
			if err != nil {
				return err
			}
			sources[ref.PolicyID] = source
		}
		if ref.PolicyVersion != uint64(source.Version) {
			return ErrConflict
		}
		if len(source.Settings.ApplicationBindings) != 0 || len(source.Settings.Applications) != 0 {
			return fmt.Errorf("%w: 서비스별 정책은 다른 서비스별 정책을 중첩할 수 없습니다", ErrInvalid)
		}
		app, err := scopedApplication(ref, source.Settings)
		if err != nil {
			return err
		}
		settings.Applications = append(settings.Applications, app)
	}
	return nil
}

func scopedApplication(ref ApplicationBinding, source ConsoleSettings) (managed.ApplicationPolicy, error) {
	d := source.Detection
	d.WebServices = []string{ref.Service}
	d.WebExecutables = nil
	d.PrivilegeRules = false
	d.RootExecAlerts = ""
	pairs, err := applicationAllowedPairs(ref.Service, source.Detection)
	if err != nil {
		return managed.ApplicationPolicy{}, err
	}
	d.AllowedPairs = pairs
	d.ServiceRuleControls = nil
	for _, rule := range source.Detection.ServiceRuleControls {
		if rule.Service == ref.Service {
			d.ServiceRuleControls = append(d.ServiceRuleControls, rule)
		}
	}
	if scopes := source.Detection.ServiceObservations; scopes != nil {
		selected := []managed.ServiceObservationPolicy{}
		for _, scope := range *scopes {
			if scope.Service == ref.Service {
				selected = append(selected, scope)
			}
		}
		d.ServiceObservations = &selected
	}
	return managed.ApplicationPolicy{Service: ref.Service, PolicyID: ref.PolicyID, PolicyVersion: ref.PolicyVersion, Detection: d, Response: source.Response}, nil
}

// A legacy origin may be an executable name. Mapping it blindly can exempt
// unrelated processes; dropping it can authorize a previously exempt signal.
func applicationAllowedPairs(service string, source managed.DetectionPolicy) ([]string, error) {
	var scoped []string
	exemptShells := make(map[string]bool)
	origins := make(map[string]bool)
	for _, name := range source.WebExecutables {
		origins[strings.ToLower(name)] = true
	}
	for _, name := range source.WebServices {
		origins[strings.ToLower(name)] = true
	}
	origins[strings.ToLower(strings.TrimSuffix(service, ".service"))] = true
	for _, pair := range source.AllowedPairs {
		origin, shell, _ := strings.Cut(pair, ":")
		if strings.EqualFold(origin, service) {
			scoped = append(scoped, pair)
			exemptShells[strings.ToLower(shell)] = true
		}
	}
	for _, pair := range source.AllowedPairs {
		origin, shell, _ := strings.Cut(pair, ":")
		origin = strings.ToLower(origin)
		if !strings.HasSuffix(origin, ".service") && origins[origin] && !exemptShells[strings.ToLower(shell)] {
			return nil, fmt.Errorf("%w: 실행 이름 예외 %s의 범위를 확인한 후 원본 정책에 %s:%s 예외를 명시하세요", ErrInvalid, pair, service, shell)
		}
	}
	return scoped, nil
}

func warningsForApplications(settings ConsoleSettings, heartbeat managed.Heartbeat, now time.Time) []string {
	warnings := warningsForSettings(settings, heartbeat, now)
	if len(settings.Applications) == 0 {
		return warnings
	}
	// A large group may share the same response and sensor prerequisites.
	// Count each distinct warning once per service without repeating the text.
	counts := make(map[string]int)
	var order []string
	for _, app := range settings.Applications {
		for _, warning := range warningsForSettings(ConsoleSettings{Detection: app.Detection, Response: app.Response}, heartbeat, now) {
			if counts[warning] == 0 {
				order = append(order, warning)
			}
			counts[warning]++
		}
	}
	for _, warning := range order {
		warnings = append(warnings, fmt.Sprintf("서비스별 정책 %d개 · %s", counts[warning], warning))
	}
	return warnings
}
