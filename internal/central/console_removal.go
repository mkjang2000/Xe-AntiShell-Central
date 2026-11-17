package central

import (
	"bytes"
	"mime"
	"net/http"
)

// Buffer the bounded grant response so the reused operator flow releases its
// transaction on error before a browser can block the network write.
type consoleRemovalBuffer struct {
	header http.Header
	status int
	bytes.Buffer
}

func (b *consoleRemovalBuffer) Header() http.Header    { return b.header }
func (b *consoleRemovalBuffer) WriteHeader(status int) { b.status = status }

func (s *Server) consoleRemoval(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		respond(w, http.StatusUnsupportedMediaType, map[string]string{"error": "application/json 형식으로 요청하세요"})
		return
	}
	buffer := &consoleRemovalBuffer{header: make(http.Header)}
	s.adminRemoval(buffer, r)
	if buffer.status >= 400 {
		message := "중앙 저장소 또는 서비스에 연결할 수 없습니다"
		switch buffer.status {
		case http.StatusBadRequest:
			message = "에이전트·등록 ID, challenge와 유효 시간(1~900초)을 확인하세요"
		case http.StatusUnauthorized:
			message = "현재 에이전트 등록 정보와 일치하지 않습니다"
		case http.StatusForbidden:
			message = "현재 정책이 일반 삭제 승인을 금지합니다"
		case http.StatusNotFound:
			message = "활성 에이전트를 찾을 수 없습니다"
		}
		respond(w, buffer.status, map[string]string{"error": message})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(buffer.status)
	_, _ = w.Write(buffer.Bytes())
}
