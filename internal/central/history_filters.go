package central

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type historyFilter struct {
	View   string `json:"view"`
	SiteID string `json:"site_id,omitempty"`
	Agent  string `json:"agent"`
	Type   string `json:"type"`
	Search string `json:"search"`
	From   string `json:"from"`
	Until  string `json:"until"`
}

func readHistoryFilter(r *http.Request, view string) (historyFilter, int64, int64, error) {
	query := r.URL.Query()
	filter := historyFilter{View: view, SiteID: selectedSite(r.Context()), Agent: query.Get("agent_id"), Type: query.Get("type"), Search: strings.TrimSpace(query.Get("q"))}
	if filter.Agent != "" && !identifierPattern.MatchString(filter.Agent) || len(filter.Type) > 160 || !validText(filter.Type, false) || len(filter.Search) > 200 || !validText(filter.Search, false) {
		return filter, 0, 0, fmt.Errorf("%w: 에이전트·유형·검색어를 확인하세요", ErrInvalid)
	}
	var bounds [2]int64
	for index, name := range []string{"from", "until"} {
		value := query.Get(name)
		if value == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || at.Year() < 1970 || at.Year() > 2261 {
			return filter, 0, 0, fmt.Errorf("%w: 조회 기간은 올바른 날짜·시간이어야 합니다", ErrInvalid)
		}
		bounds[index] = at.UnixNano()
		if index == 0 {
			filter.From = at.UTC().Format(time.RFC3339Nano)
		} else {
			filter.Until = at.UTC().Format(time.RFC3339Nano)
		}
	}
	if bounds[0] != 0 && bounds[1] != 0 && bounds[0] >= bounds[1] {
		return filter, 0, 0, fmt.Errorf("%w: 조회 종료 시각은 시작 시각보다 뒤여야 합니다", ErrInvalid)
	}
	return filter, bounds[0], bounds[1], nil
}

type historyPageCursor struct {
	At     int64         `json:"at"`
	Agent  string        `json:"agent"`
	Kind   string        `json:"kind"`
	ID     string        `json:"id"`
	Item   int64         `json:"item"`
	Filter historyFilter `json:"filter"`
}

func readHistoryCursor(r *http.Request, filter historyFilter) (historyPageCursor, error) {
	var cursor historyPageCursor
	value := r.URL.Query().Get("before")
	if value == "" {
		return cursor, nil
	}
	body, err := base64.RawURLEncoding.DecodeString(value)
	if len(value) > 4096 || err != nil || managed.DecodeStrict(body, 3072, &cursor) != nil || cursor.At < 1 || cursor.ID == "" || cursor.Filter != filter {
		return cursor, fmt.Errorf("%w: 조회 조건이 바뀌었거나 페이지 정보가 잘못되었습니다", ErrInvalid)
	}
	return cursor, nil
}

func historyCursorHeader(w http.ResponseWriter, cursor historyPageCursor) {
	body, _ := json.Marshal(cursor)
	w.Header().Set("X-Next-Cursor", base64.RawURLEncoding.EncodeToString(body))
}

func historyLimit(r *http.Request) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return 20, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 500 {
		return 0, fmt.Errorf("%w: 페이지당 개수는 1~500이어야 합니다", ErrInvalid)
	}
	return limit, nil
}
