package central

import (
	"fmt"
	"strings"
)

type historyBranch struct {
	kind, display, payload, typeValue, from, extra string
	findingItems                                   bool
}

func historyBranches(view string) []historyBranch {
	switch view {
	case "events":
		return []historyBranch{
			{kind: "event", display: "event", payload: "r.payload", typeValue: "json_extract(r.payload,'$.event_type')", from: "records r"},
			{kind: "event_bundle", display: "event", payload: "json_extract(r.payload,'$.event')", typeValue: "json_extract(r.payload,'$.event.event_type')", from: "records r"},
		}
	case "detections":
		return []historyBranch{
			{kind: "finding", display: "finding", payload: "r.payload", typeValue: "json_extract(r.payload,'$.rule_id')", from: "records r"},
			{kind: "event_bundle", display: "finding", payload: "j.value", typeValue: "json_extract(j.value,'$.rule_id')", from: "records r INDEXED BY records_history_detection_bundle_idx,json_each(r.payload,'$.findings') j", extra: "json_array_length(r.payload,'$.findings')>0 AND json_type(r.payload,'$.findings')='array' AND j.type='object'", findingItems: true},
		}
	default:
		return []historyBranch{{kind: "audit", display: "audit", payload: "r.payload", typeValue: "json_extract(r.payload,'$.action')", from: "records r"}}
	}
}

// Limit each independently indexed branch before the final bounded merge. No
// user-supplied identifier or JSON path enters SQL; all filter values are bound.
func buildHistoryQuery(filter historyFilter, from, until int64, cursor historyPageCursor, limit int) (string, []any) {
	return buildHistoryBranchesQuery(filter, from, until, cursor, limit, historyBranches(filter.View))
}

func buildLegacyHistoryQuery(agent, kind string, cursor consoleHistoryCursor, limit int) (string, []any) {
	branches := []historyBranch{{kind: kind, display: "event", payload: "r.payload", from: "records r"}}
	if kind == "detections" {
		branches = []historyBranch{
			{kind: "finding", display: "finding", payload: "r.payload", from: "records r"},
			{kind: "event_bundle", display: "event", payload: "r.payload", from: "records r INDEXED BY records_history_detection_bundle_idx", extra: "json_array_length(r.payload,'$.findings')>0"},
		}
	}
	query, args := buildHistoryBranchesQuery(historyFilter{Agent: agent, SiteID: cursor.FilterSite}, 0, 0, historyPageCursor{At: cursor.At, Agent: cursor.AgentID, Kind: cursor.Kind, ID: cursor.ID}, limit, branches)
	return query, args
}

func buildHistoryBranchesQuery(filter historyFilter, from, until int64, cursor historyPageCursor, limit int, specs []historyBranch) (string, []any) {
	var branches, names []string
	var args []any
	for index, branch := range specs {
		name := fmt.Sprintf("history_%d", index)
		names = append(names, "SELECT * FROM "+name)
		item := "0"
		if branch.findingItems {
			item = "CAST(j.key AS INTEGER)"
		}
		fromTable := branch.from
		conditions := []string{"1"}
		if filter.SiteID != "" {
			fromTable = strings.Replace(fromTable, "records_history_detection_bundle_idx", "records_site_detection_bundle_idx", 1)
			conditions = append(conditions, "r.site_id=?")
			args = append(args, filter.SiteID)
		}
		if branch.kind != "" {
			conditions = append(conditions, "r.kind='"+branch.kind+"'")
		}
		if branch.extra != "" {
			conditions = append(conditions, branch.extra)
		}
		if filter.Agent != "" {
			conditions = append(conditions, "r.agent_id=?")
			args = append(args, filter.Agent)
		}
		if from != 0 {
			conditions = append(conditions, "r.received_at_ns>=?")
			args = append(args, from)
		}
		if until != 0 {
			conditions = append(conditions, "r.received_at_ns<?")
			args = append(args, until)
		}
		if filter.Type != "" {
			conditions = append(conditions, branch.typeValue+"=?")
			args = append(args, filter.Type)
		}
		if filter.Search != "" {
			conditions = append(conditions, "instr(lower(CAST("+branch.payload+" AS TEXT)),lower(?))>0")
			args = append(args, filter.Search)
		}
		if cursor.At != 0 {
			switch {
			case branch.kind == "":
				conditions = append(conditions, "(r.received_at_ns,r.agent_id,r.kind,r.record_id)<(?,?,?,?)")
				args = append(args, cursor.At, cursor.Agent, cursor.Kind, cursor.ID)
			case branch.kind < cursor.Kind:
				conditions = append(conditions, "(r.received_at_ns,r.agent_id)<=(?,?)")
				args = append(args, cursor.At, cursor.Agent)
			case branch.kind > cursor.Kind:
				conditions = append(conditions, "(r.received_at_ns,r.agent_id)<(?,?)")
				args = append(args, cursor.At, cursor.Agent)
			case branch.findingItems:
				conditions = append(conditions, "(r.received_at_ns,r.agent_id,r.record_id,"+item+")<(?,?,?,?)")
				args = append(args, cursor.At, cursor.Agent, cursor.ID, cursor.Item)
			default:
				comparison := "<"
				if cursor.Item > 0 {
					comparison = "<="
				}
				conditions = append(conditions, "(r.received_at_ns,r.agent_id,r.record_id)"+comparison+"(?,?,?)")
				args = append(args, cursor.At, cursor.Agent, cursor.ID)
			}
		}
		order := "r.received_at_ns DESC,r.agent_id DESC,r.record_id DESC"
		if branch.kind == "" {
			order = "r.received_at_ns DESC,r.agent_id DESC,r.kind DESC,r.record_id DESC"
		}
		if branch.findingItems {
			order += "," + item + " DESC"
		}
		branches = append(branches, fmt.Sprintf("%s AS (SELECT r.agent_id,'%s' AS display_kind,r.record_id,r.received_at_ns,%s AS payload,r.kind AS source_kind,%s AS item FROM %s WHERE %s ORDER BY %s LIMIT ?)", name, branch.display, "NULL", item, fromTable, strings.Join(conditions, " AND "), order))
		args = append(args, limit+1)
	}
	query := "WITH " + strings.Join(branches, ",") + " SELECT agent_id,display_kind,record_id,received_at_ns,payload,source_kind,item FROM (" + strings.Join(names, " UNION ALL ") + ") ORDER BY received_at_ns DESC,agent_id DESC,source_kind DESC,record_id DESC,item DESC LIMIT ?"
	args = append(args, limit+1)
	return query, args
}
