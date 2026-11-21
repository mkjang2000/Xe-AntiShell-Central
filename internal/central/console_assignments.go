package central

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

// consolePreviewComparisons bounds how many distinct current settings one
// preview returns. Further groups still list their hosts without settings.
const consolePreviewComparisons = 32

// consoleAssignment names the console template behind an agent's desired
// revision. TemplateState compares the deployed settings with the template's
// latest saved settings: current, changed (saved after deployment) or missing.
type consoleAssignment struct {
	PolicyID      string `json:"desired_policy_id,omitempty"`
	TemplateState string `json:"policy_template_state,omitempty"`
}

// consoleResponse is the signed desired revision's default response mode and
// the distinct service-binding modes that differ from it, weakest first. It
// covers console and directly issued policies alike.
type consoleResponse struct {
	Mode         string   `json:"desired_response_mode,omitempty"`
	ServiceModes []string `json:"desired_service_response_modes,omitempty"`
}

var responseModeStrength = map[string]int{"observe": 0, "would_block": 1, "enforce": 2}

func desiredResponse(mode string, applicationModes []string) consoleResponse {
	response := consoleResponse{Mode: mode}
	seen := map[string]bool{mode: true}
	for _, other := range applicationModes {
		if other != "" && !seen[other] {
			seen[other] = true
			response.ServiceModes = append(response.ServiceModes, other)
		}
	}
	sort.SliceStable(response.ServiceModes, func(i, j int) bool {
		return responseModeStrength[response.ServiceModes[i]] < responseModeStrength[response.ServiceModes[j]]
	})
	return response
}

// consoleDesiredResponses reads response modes from each agent's signed
// desired policy; SQLite extracts the few fields so whole policies are not
// decoded on every console refresh.
func consoleDesiredResponses(ctx context.Context, tx *sql.Tx) (map[string]consoleResponse, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.agent_id,COALESCE(json_extract(CAST(p.signed_json AS TEXT),'$.policy.response.mode'),''),
(SELECT json_group_array(json_extract(value,'$.response.mode')) FROM json_each(CAST(p.signed_json AS TEXT),'$.policy.applications'))
FROM agents a JOIN policies p ON (p.agent_id,p.enrollment_id,p.revision)=(a.agent_id,a.enrollment_id,a.desired_policy_revision)
WHERE a.desired_policy_revision>0 AND (?='' OR a.site_id=?) ORDER BY a.agent_id LIMIT 1000`, selectedSite(ctx), selectedSite(ctx))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	responses := make(map[string]consoleResponse)
	for rows.Next() {
		var id, mode string
		var applications []byte
		if err = rows.Scan(&id, &mode, &applications); err != nil {
			return nil, err
		}
		var modes []string
		if err = json.Unmarshal(applications, &modes); err != nil {
			return nil, err
		}
		responses[id] = desiredResponse(mode, modes)
	}
	return responses, rows.Err()
}

func assignedTemplate(policyID string, deployed ConsoleSettings, latest map[string][]byte) (consoleAssignment, error) {
	assignment := consoleAssignment{PolicyID: policyID}
	if policyID == "" {
		return assignment, nil
	}
	saved, ok := latest[policyID]
	if !ok {
		assignment.TemplateState = "missing"
		return assignment, nil
	}
	body, err := json.Marshal(deployed)
	if err != nil {
		return assignment, err
	}
	assignment.TemplateState = "changed"
	if bytes.Equal(body, saved) {
		assignment.TemplateState = "current"
	}
	return assignment, nil
}

// consoleCurrentPolicy groups preview targets that currently hold the same
// policy. Kind is console (settings issued by this console), direct (a policy
// issued without console settings) or none (no central policy yet).
type consoleCurrentPolicy struct {
	Kind     string           `json:"kind"`
	PolicyID string           `json:"policy_id,omitempty"`
	Settings *ConsoleSettings `json:"settings,omitempty"`
	Omitted  bool             `json:"comparison_omitted,omitempty"`
	AgentIDs []string         `json:"agent_ids"`
}

func consoleCurrentPolicies(ctx context.Context, tx *sql.Tx, targets []consoleDeployTarget) ([]consoleCurrentPolicy, error) {
	groups := []consoleCurrentPolicy{}
	index := make(map[string]int)
	compared := 0
	for _, target := range targets {
		item := consoleCurrentPolicy{Kind: "none"}
		if target.CurrentRevision > 0 {
			item.Kind = "direct"
			var policyID string
			var body []byte
			err := tx.QueryRowContext(ctx, `SELECT COALESCE(json_extract(CAST(p.signed_json AS TEXT),'$.policy.policy_id'),''),s.settings_json FROM policies p
LEFT JOIN console_policy_settings s ON (s.agent_id,s.enrollment_id,s.revision)=(p.agent_id,p.enrollment_id,p.revision)
WHERE (p.agent_id,p.enrollment_id,p.revision)=(?,?,?)`, target.AgentID, target.EnrollmentID, target.CurrentRevision).Scan(&policyID, &body)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			item.PolicyID = policyID
			if len(body) > 0 {
				var settings ConsoleSettings
				if err = json.Unmarshal(body, &settings); err != nil {
					return nil, err
				}
				item.Kind, item.Settings = "console", &settings
			}
		}
		key, err := consoleHash([]any{item.Kind, item.PolicyID, item.Settings})
		if err != nil {
			return nil, err
		}
		if position, ok := index[key]; ok {
			groups[position].AgentIDs = append(groups[position].AgentIDs, target.AgentID)
			continue
		}
		if item.Settings != nil {
			if compared == consolePreviewComparisons {
				item.Settings, item.Omitted = nil, true
			} else {
				compared++
			}
		}
		item.AgentIDs = []string{target.AgentID}
		index[key] = len(groups)
		groups = append(groups, item)
	}
	return groups, nil
}
