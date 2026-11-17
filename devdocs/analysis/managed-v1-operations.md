# Managed v1 운영 절차와 검증 범위

## 적용 범위

이번 구현은 단일 중앙 서버와 에이전트의 등록, 이벤트 전송, 상태 보고,
서명 정책 수신, 일회용 삭제 승인을 연결한다. 중앙 저장소는 v1에서 별도
SQLite 데이터베이스를 사용한다. PostgreSQL, 중앙 서버 다중화, 운영자별
권한 분리와 중앙 관리 웹 UI는 후속 범위다. 현재 웹 패널은 에이전트의
탐지 이력과 상태를 조회하는 모니터링 화면이다.

초기 연결은 **탐지·모니터링 모드**를 기준으로 한다. 아래 정책 예시도
`observe` / `none`을 사용한다. 자동 테스트의 서명·권한·삭제 승인 검증을
운영 서버에서 실제 프로세스 종료나 패키지 삭제까지 검증한 것으로
해석하면 안 된다. 아래 이름, ID와 경로는 모두 일반 운영 예시다.

중앙 명령은 중앙 서버에서, `sentinel` 에이전트 명령은 별도로 설치한
에이전트 서버에서 root로 실행한다. 에이전트 패키지와 로컬 모니터링 패널은
[Xe-AntiShell 저장소](https://github.com/mkjang2000/Xe-AntiShell)에서 관리한다.

## 중앙 서비스 초기화

중앙 전용 RPM은 `xe-antishell-central` 전용 계정을 만들며 중앙 서비스는 이 계정으로
실행한다. 초기화는 설치 후 root로 수행한다. 초기화가 생성하는 CA, 서버
인증서, 정책 서명 키, 운영자 자격 증명과 데이터베이스는 기존 파일을
덮어쓰지 않는다. 상태 디렉터리는 0700, 내부 파일은 0600이다.

```sh
sentinel-central init --state-dir /var/lib/xe-antishell-central \
  --hosts localhost,127.0.0.1,::1

sentinel-central enrollment-token \
  --state-dir /var/lib/xe-antishell-central \
  --agent-id HOST_ID \
  --output-file /root/xe-enrollment-token \
  --ttl 1h

systemctl enable --now sentinel-central
```

systemd의 `StateDirectory`가 상태 디렉터리의 런타임 소유권을 관리한다.
설치기는 초기화를 수행하지 않으며 기존 상태·키·DB를 보존한다.
`HOST_ID`는 실제 에이전트 ID로 바꾼다. 토큰은 특정 에이전트에 귀속되며,
최대 유효 기간은 24시간이다. 명령 출력에는 파일 경로만 표시하고 토큰
내용을 출력하지 않는다. 토큰을 명령 인자나 환경변수에 직접 넣지 않는다.
다른 서버에 설치할 때는 토큰과 CA를 별도의 인증된 경로로 전달한다.

기본 리스너는 다음과 같다.

| 용도 | 기본 주소 | 인증 |
| --- | --- | --- |
| 에이전트 HTTPS | `127.0.0.1:9443` | 등록 토큰 또는 등록 후 mTLS |
| 운영자 API | `127.0.0.1:9444` | 별도 운영자 bearer 자격 증명 |

기본값은 같은 호스트에서 연결할 때 사용한다. 원격 에이전트를 받으려면 인증서의
SAN에 실제 접속 이름을 포함하고, `serve --listen IP:9443
--allow-non-loopback`을 명시해야 한다. 운영자 API는 계속 loopback만 허용한다.
서비스는 방화벽 규칙을 자동으로 열지 않는다. 중앙 서버의 CA 개인 키와
정책 개인 키를 에이전트에 복사하면 안 된다.

원격 중앙 이름이 `central.example.invalid`라면 새 중앙 초기화 시
`--hosts central.example.invalid,localhost,127.0.0.1,::1`을 지정한다.
이미 초기화된 중앙의 이름 변경은 PKI 회전 계획에 따라 별도 진행하며
기존 상태를 지우거나 다시 초기화하지 않는다. 새 중앙에만 다음과 같은
서비스 override를 명시적으로 적용할 수 있다.

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/sentinel-central serve --state-dir /var/lib/xe-antishell-central --listen 0.0.0.0:9443 --allow-non-loopback --admin-listen 127.0.0.1:9444
```

서비스를 시작하기 전에 포트와 인증서 SAN, 접근 경로를 확인한다. 운영자 API의
포트를 바꿔야 하면 `systemctl edit sentinel-central.service`로 다음과 같은
호스트별 override를 작성할 수 있다. 아래 19444는 빈 포트를 선택하는 예시다.

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/sentinel-central serve --state-dir /var/lib/xe-antishell-central --listen 127.0.0.1:9443 --admin-listen 127.0.0.1:19444
```

설정 후 `systemctl daemon-reload`와 `systemctl restart sentinel-central`을
실행한다. 아래 curl 예제의 포트도 선택한 운영자 API 포트로 맞춘다. 운영자
API는 loopback 바인딩을 유지하며 에이전트 HTTPS 포트와 구분한다.

## 에이전트 등록과 연결 확인

각 에이전트의 ID를 따로 정하고 중앙에서 해당 ID의 일회용 토큰을 발급한다.
중앙의 `ca.pem` 공개 인증서와 해당 토큰만 인증된 별도 경로로 에이전트에
전달한다. 아래 예시는 공개 인증서를 `/etc/xe-antishell/central-ca.pem`,
토큰을 root 소유의 0600 `/root/xe-enrollment-token`으로 준비한 경우다.
개인 키와 중앙 상태 디렉터리 전체는 전달하지 않는다.

에이전트에서 `sentineld`를 실행한 상태로 root 등록 명령을 실행한다.
CA 파일은 등록 응답에서 신뢰를 새로 얻는 용도가 아니라, 운영자가 미리
전달한 신뢰 기준이다. URL은 인증서 SAN과 일치하는 실제 중앙 이름으로 바꾼다.

```sh
sentinel managed enroll \
  --central https://central.example.invalid:9443 \
  --agent-id HOST_ID \
  --ca-file /etc/xe-antishell/central-ca.pem \
  --token-file /root/xe-enrollment-token \
  --recovery-file /root/xe-offline-recovery

sentinel managed status
```

CLI는 256비트 난수 복구 코드를 0600 파일에 기록하고 `fsync`한 뒤 등록
요청을 보낸다. 같은 파일을 지정한 재시도에서는 기존 코드를 사용한다.
데몬은 복구 코드의 등록 대상별 검증값을 저장하며 코드를 패널이나 일반
상태 응답으로 내보내지 않는다. 복구 파일은 에이전트 데이터베이스와
별도로 안전하게 보관한다.

에이전트는 개인 키와 CSR을 먼저 저장한다. 중앙에서 등록을 처리한 뒤
응답이 유실되어도, 유효 기간 내 동일한 토큰·대상·CSR로 재시도하면 원래
인증서를 반환한다. CSR 또는 에이전트가 바뀐 재사용은 거부한다. 등록 후
요청은 중앙 CA가 서명한 클라이언트 인증서의 agent ID와 enrollment ID에
귀속된다. 재등록하면 이전 인증서는 중앙에서 거부한다.

상태의 `enrolled`, `last_contact_at`, `delivery.pending`,
`delivery.acknowledged`, `delivery.lost_records`, `policy`를 확인한다.
이벤트와 파생 탐지 결과는 로컬 저장과 전송 outbox를 함께 커밋한다.
원본 수집 sequence와 별도의 연속 전송 sequence를 사용하며, 중앙의
저장 커밋 이후 ACK를 받아야 outbox에서 제거한다. 재전송은 중복 저장을
만들지 않는다. 전송 대기열은 256MiB로 제한되며, 초과 손실은
`lost_records`로 표시된다. 네트워크 복구만으로 이미 집계된 손실이 복원되는
것은 아니다.

## 운영자 API 사용

운영자 자격 증명은 `/var/lib/xe-antishell-central/operator-token`에 있다.
현재는 단일 운영자 bearer 방식이며 사용자별 RBAC를 제공하지 않는다.
아래처럼 헤더 파일을 만들어 curl의 인자와 터미널 출력에 비밀을 남기지
않는다. 명령은 root로 실행한다.

```sh
umask 077
python3 - <<'PY'
import os
from pathlib import Path
token = Path('/var/lib/xe-antishell-central/operator-token').read_text().strip()
fd = os.open('/root/xe-central-admin.headers', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write('Authorization: Bearer ' + token + '\n')
PY

curl --fail --silent --show-error \
  --header @/root/xe-central-admin.headers \
  --output /root/xe-central-agents.json \
  http://127.0.0.1:9444/admin/agents

curl --fail --silent --show-error \
  --header @/root/xe-central-admin.headers \
  --output /root/xe-central-audit.json \
  'http://127.0.0.1:9444/admin/audit?limit=100'
```

추가 조회는 `/admin/history?agent_id=HOST_ID&kind=event_bundle&limit=100`을
사용한다. 조회 limit은 1~500이다. `/admin/agents`에는 마지막 heartbeat,
자원 표본, 활성·희망 정책 revision과 적용 결과가 포함된다. API 원문 파일은
프로세스 정보와 탐지 증거를 포함할 수 있으므로 제한된 위치에서 관리한다.
curl의 `--verbose`, `--trace`는 인증 헤더를 기록할 수 있어 이 절차에 넣지 않는다.

## 보안 정책 배포

등록 직후에는 중앙 정책을 자동 배포하지 않는다. `GET /v1/policy`의 204는
현재 호스트의 로컬 탐지 기준을 유지한다는 의미다. 새 정책은 해당 호스트의
기존 web executable, 서비스, shell, 예외 목록과 수집기 입력 범위를 보존해
작성한다. 중앙 정책이 수집기 설치나 필터 범위까지 자동으로 바꾸지는 않는다.

`/root/xe-policy.json`은 공용 `github.com/mkjang2000/Xe-AntiShell/protocol/managed`의 전체 Policy 형식을
사용한다. 주요 항목은 다음과 같다.

- `schema_version`: `"1"`, `policy_id`, 증가하는 `revision`.
- `agent_id`, `enrollment_id`: 대상의 현재 등록 ID.
- `issued_at`, `expires_at`: RFC3339 시각. 정책 유효 기간은 최대 366일.
- `detection`: `enabled`, `web_executables`, `web_services`, `shells`, `allowed_pairs`.
- `response`: `mode`, `action`, `risk_threshold`, `min_confidence`, `required_capabilities`.
- `uninstall_mode`: `allow`, `approval_required`, `deny`.
- `monitoring`: `enabled`, `sample_interval_seconds` 5~3600, `process_limit` 1~2000.

첫 검증 정책의 response는 아래 값으로 둔다.

```json
{
  "mode": "observe",
  "action": "none",
  "risk_threshold": 90,
  "min_confidence": 0.95,
  "required_capabilities": []
}
```

완성한 전체 정책을 전송한다.

```sh
curl --fail --silent --show-error \
  --header @/root/xe-central-admin.headers \
  --header 'Content-Type: application/json' \
  --data-binary @/root/xe-policy.json \
  --output /root/xe-policy-signed.json \
  http://127.0.0.1:9444/admin/policy

sentinel managed status
```

중앙이 정책을 서명하고 에이전트가 서명, 등록 대상, 시각, revision을 검증한다.
같은 revision의 다른 내용과 revision 역행은 거부한다. `desired_revision`만
증가하고 `active_revision`이 그대로라면 `result`와 `error`를 확인한다. 로컬
수집 범위 밖의 shell을 추가하거나 지원하지 않는 종료 기능을 요구하면
정책이 거부될 수 있다. `enforce`는 별도의 호스트 로컬 종료 opt-in과 실제
지원 기능 검증도 필요하다.

정책이 만료되면 마지막 승인 탐지 기준은 유지하고 자동 대응은 비활성화한다.
중앙 연결 실패 시에도 로컬 탐지를 계속하며 전송을 재시도한다. 일반 사용자의
정책 변조는 서명과 로컬 권한으로 통제하지만, 호스트 root가 실행 파일·DB·
커널 자체를 바꾸는 행위를 이 구조만으로 막는다고 보장하지 않는다.

## 일반 삭제 승인과 오프라인 복구

일반 삭제 승인은 TOTP 숫자를 공유하는 방식이 아니다. 에이전트가 생성한
challenge에 중앙이 서명한 짧은 유효 기간의 일회용 승인이다. 승인에는
agent ID, enrollment ID, challenge, grant ID, `uninstall` 동작, 만료가 묶인다.

```sh
umask 077
sentinel managed challenge > /root/xe-removal-challenge.json
sentinel managed status > /root/xe-agent-status.json
```

운영자는 위 두 파일을 확인한 뒤 `/root/xe-removal-request.json`을 작성한다.
필드는 `agent_id`, `enrollment_id`, `challenge`, `ttl_seconds`이며 TTL은
기본 300초, 최대 900초다. `uninstall_mode: deny` 정책은 일반 승인을 거부한다.

```sh
curl --fail --silent --show-error \
  --header @/root/xe-central-admin.headers \
  --header 'Content-Type: application/json' \
  --data-binary @/root/xe-removal-request.json \
  --output /root/xe-removal-grant.json \
  http://127.0.0.1:9444/admin/removal

sentinel managed authorize-removal \
  --operation OPERATION_ID \
  --grant-file /root/xe-removal-grant.json
```

`OPERATION_ID`에는 challenge 파일의 `operation_id`를 넣는다. 에이전트는
승인 소비와 감사 이벤트를 함께 저장한다. 같은 승인으로 다른 작업을
승인할 수 없다. 응답 유실 시 같은 작업의 재시도는 허용한다. 일반 승인
절차는 중앙 ACK가 필요하며, 패키지 삭제 직전 시작 감사도 전송한다.

중앙과 통신할 수 없는 최후의 복구에는 설치 시 보관한 파일을 사용한다.

```sh
sentinel managed recover-removal \
  --operation OPERATION_ID \
  --code-file /root/xe-offline-recovery
```

복구 코드는 등록 세대에 귀속된 일회용 값이다. 오프라인 복구에서는 중앙
ACK를 요구하지 않으며 감사 의무는 로컬에 남긴다. 통신이 끊긴 상태에서
삭제되어도 중앙 전송을 반드시 완료할 수 있다는 보장은 없다.

에이전트 RPM의 최종 삭제 `%preun`은 서비스 중지 전에 `sentinel managed removal-check`를
호출한다. 관리 상태에서 승인이나 필요한 ACK가 없으면 일반 패키지 삭제를
중단한다. 미등록 에이전트는 일반 삭제를 허용한다. 실제 삭제 명령은 운영
중단을 수반하므로 이 문서의 검증 절차에 포함하지 않았다. root의
`rpm --noscripts`, 직접 파일 삭제, 서비스 중지까지 막을 수 있는 보호는 아니다.

중앙 전용 RPM은 에이전트 명령이나 위 삭제 승인 hook에 의존하지 않는다.
중앙 패키지 삭제는 중앙 서비스만 중지하며 상태 파일을 삭제하지 않는다.

## 운영상 남은 범위

- 중앙 CA는 초기 발급 기준 5년, 서버 인증서는 1년, 에이전트 인증서는 90일이다.
  자동 인증서 갱신·회전 절차는 아직 없으므로 만료 전에 별도 작업이 필요하다.
- `POST /admin/revoke`는 `{"agent_id":"HOST_ID"}`를 받아 현재 인증서를
  중앙에서 즉시 거부한다. 인증서 철회는 로컬 복구 코드의 대체 수단이 아니다.
- 중앙 상태 디렉터리는 CA·정책 키와 DB를 함께 포함한다. SQLite 운영 백업은
  서비스를 정지한 상태의 일관된 복사나 SQLite backup 방식을 사용한다.
  실행 중 `central.db` 하나만 복사하면 WAL의 최근 커밋을 놓칠 수 있다.
- 중앙 DB의 장기 보존·용량 관리, 인증서 회전, PostgreSQL 이전, 중앙 웹 관리,
  다중 운영자 권한 관리는 후속 구현·운영 검증이 필요하다.
- TPM·프로세스 무결성 검증은 이번 우선 범위에서 제외되어 있다.
