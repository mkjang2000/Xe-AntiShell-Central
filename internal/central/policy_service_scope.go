package central

import (
	"encoding/json"
	"fmt"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const (
	serviceScopeSelected     = "selected"
	serviceScopeAllListening = "all_listening"
)

func (settings ConsoleSettings) validateServiceScope() error {
	switch settings.ServiceScope {
	case "":
		return nil
	case serviceScopeSelected:
		if len(settings.Detection.WebExecutables) != 0 || len(settings.Detection.WebServices) == 0 {
			return fmt.Errorf("%w: 지정된 서비스 모드에서는 시스템 서비스 이름을 하나 이상 선택하세요", ErrInvalid)
		}
		for _, service := range settings.Detection.WebServices {
			if !managed.ValidApplicationService(service) {
				return fmt.Errorf("%w: 지정된 서비스 모드에서는 정확한 .service 이름만 사용할 수 있습니다", ErrInvalid)
			}
		}
		// The wire validator also rejects duplicates, including case variants.
		return nil
	case serviceScopeAllListening:
		if len(settings.Detection.WebExecutables)+len(settings.Detection.WebServices) != 0 {
			return fmt.Errorf("%w: 발견된 모든 서비스 모드에서는 실행 파일과 서비스를 따로 지정할 수 없습니다", ErrInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: 웹 출처 서비스 범위를 확인하세요", ErrInvalid)
	}
}

func validateConsoleWirePolicy(policy managed.Policy) error {
	if err := policy.Validate(); err != nil {
		// The protocol reason names the rejected field for the operator.
		return fmt.Errorf("%w: 탐지·대응·삭제 또는 모니터링 설정을 확인하세요 (%v)", ErrInvalid, err)
	}
	body, err := json.Marshal(policy)
	if err != nil || len(body) > managed.MaxPolicyBytes-1024 {
		return fmt.Errorf("%w: 정책 설정이 너무 큽니다", ErrInvalid)
	}
	return nil
}

func (settings ConsoleSettings) withListeningServices(services []string) ConsoleSettings {
	if settings.ServiceScope == serviceScopeAllListening {
		settings.Detection.WebServices = services
	}
	return settings
}

type consoleServiceTargets struct {
	AgentIDs []string `json:"agent_ids"`
	Services []string `json:"services"`
}

func consoleServiceTargetGroups(targets []consoleDeployTarget) []consoleServiceTargets {
	groups := []consoleServiceTargets{}
	index := make(map[string]int)
	for _, target := range targets {
		if target.ServiceScopeHash == "" {
			continue
		}
		position, ok := index[target.ServiceScopeHash]
		if !ok {
			position = len(groups)
			index[target.ServiceScopeHash] = position
			groups = append(groups, consoleServiceTargets{Services: target.listeningServices})
		}
		groups[position].AgentIDs = append(groups[position].AgentIDs, target.AgentID)
	}
	return groups
}
