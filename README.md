# Xe-AntiShell-Central

[Xe-AntiShell](https://github.com/mkjang2000/Xe-AntiShell) 에이전트를 위한
독립 중앙 관리 서비스다. 에이전트 등록, mTLS 이벤트 전송과 ACK, 상태 보고,
서명 정책, 일회용 에이전트 삭제 승인 및 인증서 철회를 제공한다. 프로젝트
코드는 MIT이며, 외부 의존성 고지는 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)에 있다.

한국어 중앙 웹패널에서 서버 현황과 기능 지원 상태, 탐지 이력, 정책·그룹,
등록 토큰 및 일회용 삭제 승인을 관리한다. 다중 운영자 권한, 자동 인증서
갱신, PostgreSQL 및 중앙 서버 다중화는 후속 범위다. 에이전트 탐지와 로컬 모니터링 패널은 별도 저장소에서
배포한다. 이 패키지는 중앙 실행 파일 하나와 전용 서비스만 설치한다.

## 빌드와 검증

Linux, Go 1.22 이상, GNU make, Bash, Git, Python 3.9 이상이 필요하다.
브라우저 스크립트 검증에는 Node.js 22 이상이 필요하며 서비스 실행에는 필요하지 않다.
검증용 race 테스트에는 C 컴파일러도 필요하다. Go 모듈은 고정 버전으로
다운로드하며, SQLite는 `modernc.org/sqlite`의 pure Go 드라이버를 사용한다.
공용 계약은 `github.com/mkjang2000/Xe-AntiShell/protocol v0.1.0`에 고정한다.

```sh
make verify
make static
./build/sentinel-central version
```

`make verify`는 소스·문서 검사, shell/패키징 회귀 검사, 형식 검사,
브라우저 스크립트 테스트, `go vet`, race 테스트와 정적 실행 파일 빌드를 수행한다. 구조는
[Project_tree.md](Project_tree.md)에 정리되어 있다.

## 설치

RPM 빌드에는 `rpm`, `rpmbuild`, systemd RPM 매크로와 GNU tar가 추가로
필요하다. 빌드는 임시 디렉터리에서 수행하며 호스트 패키지를 설치하지 않는다.
출력은 기본 `dist/rpm/`이다. 동일 파일 덮어쓰기는 `--force`로 명시한다.

```sh
make rpm
sudo ./install.sh --rpm dist/rpm/xe-antishell-central-0.1.0-3.el9.x86_64.rpm
# 또는 현재 소스를 빌드한 뒤 설치한다.
sudo ./install.sh --build
```

설치 대상 RPM의 의존성은 사전에 설치되어 있어야 한다. 설치기는 방화벽,
PKI, DB 초기화 또는 에이전트 설정을 변경하지 않는다. 기존 `state.json`이
있으면 중앙 서비스만 활성화·시작한다. 초기 상태가 없으면 패키지만 설치하고
아래 명시적 초기화를 안내한다. 기존 `xe-antishell` 통합 RPM이 중앙 파일을
소유한다면 먼저 백업과 파일 소유권 이전을 포함한 별도 마이그레이션이 필요하다.

## 최초 초기화와 실행

**새 중앙 서버에서 한 번만** root로 실행한다. 기존 중앙 서버에서는 CA,
정책 키와 DB를 보존하고 초기화를 다시 수행하지 않는다. `init`은 기존 파일을
덮어쓰지 않는다. 원격 에이전트가 사용할 이름을 인증서 SAN에 포함한다.

```sh
sudo sentinel-central init --state-dir /var/lib/xe-antishell-central \
  --hosts localhost,127.0.0.1,::1
sudo sentinel-central init-panel --state-dir /var/lib/xe-antishell-central
sudo systemctl enable --now sentinel-central.service
```

상태는 `/var/lib/xe-antishell-central`에 저장한다. 전용 계정은
`xe-antishell-central`이며 systemd `StateDirectory`가 런타임 소유권을
관리한다. 기본 에이전트 HTTPS 주소는 `127.0.0.1:9443`, 운영자 API는
`127.0.0.1:9444`다. 기존 systemd override는 그대로 사용한다.

원격 에이전트를 받으려면 인증서 SAN과 접근 경로를 확인한 뒤 systemd
override에서 `serve --listen IP:9443 --allow-non-loopback`을 명시한다.
`--admin-listen`은 계속 loopback만 허용한다. TLS와 네트워크 접근 정책은
운영자가 별도로 구성한다.

## 중앙 웹패널

`init-panel`은 기본 사용자 `admin`의 임의 비밀번호를 생성한다. 비밀번호는
표준 출력에 표시하지 않고 상태 디렉터리의 `panel-initial-password`에
0600 권한으로 저장한다. `--username`, `--password-file`로 변경할 수 있다.
이미 존재하는 인증 파일은 덮어쓰지 않는다. 운영 중인 전용 서비스 계정으로
초기화하려면 다음과 같이 실행한다.

```sh
sudo -u xe-antishell-central sentinel-central init-panel \
  --state-dir /var/lib/xe-antishell-central
sudo systemctl restart sentinel-central.service
```

기본 주소는 `http://127.0.0.1:9089`이다. 서비스 계정이 `panel-auth.json`을
읽을 수 있어야 한다. `serve --panel-listen ''`로 패널을 끌 수 있다.
외부 접속은 `--panel-listen 0.0.0.0:9089 --allow-non-loopback-panel`로
명시한다. 에이전트 API의 `--allow-non-loopback`과는 별도 설정이다.
패널 HTTPS는 `--panel-tls-cert /path/cert.pem --panel-tls-key /path/key.pem`으로
구성한다.

Cloudflare Tunnel처럼 외부 HTTPS를 내부 HTTP로 전달한다면 `serve` 옵션에
외부 주소를 명시한다. 아래 도메인은 운영 주소로 교체한다.

```sh
sentinel-central serve --state-dir /var/lib/xe-antishell-central \
  --panel-public-origin https://console.example.com
```

기존 `--listen`, `--admin-listen`, `--panel-listen` 사용자 설정도 함께 유지한다.
Cloudflare의 서비스 유형은 **HTTP**, URL은 **127.0.0.1:9089**로 설정한다.
브라우저의 `https://console.example.com`과 내부 서비스의 `http://127.0.0.1:9089`는
서로 다른 연결이다. HTTP 패널에 HTTPS로 연결하면 502 오류가 발생한다.
HTTP Host Header override는 비워 외부 호스트 이름을 유지한다.

외부 Origin은 실제 연결 상대가 신뢰한 프록시이고 요청 Host도 일치할 때만
사용한다. 기본 프록시 범위는 같은 서버의 `127.0.0.1/32,::1/128`이며 다른
배치는 `--panel-trusted-proxies`로 정확한 CIDR을 지정한다. 외부 HTTPS 세션은
Secure 쿠키를 사용하고, localhost 포트포워딩은 기존 HTTP 접속을 유지한다.
`Forwarded`, `X-Forwarded-*`, `CF-Connecting-IP`는 신뢰하지 않는다.
이 설정은 Cloudflare Access 인증을 대신하지 않으며 콘솔 로그인·CSRF 검사는
계속 적용된다. 로그인 제한은 실제 프록시 연결 상대에 함께 적용된다.

화면에는 다음 기능이 있다.

- 전체 현황, 서버별 연결·정책 상태와 마지막 보고 시각
- CPU·메모리·디스크·I/O·네트워크·프로세스 목록과 기능 가용성
- 버전이 있는 그룹·정책 편집, 대상 미리보기 후 명시적 배포
- 탐지·수집 이력과 중앙 관리 감사 이력
- 서버 등록 토큰, 일회용 삭제 승인 파일 발급 및 등록 철회

정책에서 탐지, 차단 점수·신뢰도·필수 기능, 삭제 통제, 자원 수집과
무결성 검사를 설정할 수 있다. 무결성 설정은 현재 중앙에 보관하는 적용 대기
항목이며, v1 에이전트에 실제 실행되었다고 표시하지 않는다. 정책 배포 완료는
에이전트 적용 완료와 구분한다. 차단은 에이전트의 지원 기능과 로컬 차단 허용
조건도 충족해야 한다. 기존 운영 정책은 패널 설치로 변경되지 않는다.

그룹 편집은 정책을 자동 배포하지 않는다. 배포 미리보기 이후 정책·그룹·등록
상태가 바뀌면 다시 미리보기해야 한다. 동시에 수정한 편집 내용은 이전 버전을
덮어쓰지 않고 충돌로 알려준다. 자원 값은 최신 heartbeat의 스냅샷이며 장기
성능 시계열은 제공하지 않는다.

삭제 승인(OTP)은 6자리 TOTP가 아니라 대상 서버·등록 세대·삭제 요청값에
묶인 짧은 유효기간의 서명 승인 파일이다. 에이전트에서 삭제 요청을 만든 뒤
그 요청값을 패널에 입력하여 파일을 발급하고 에이전트 삭제 명령에 전달한다.
정확한 명령은 아래 운영 문서를 따른다. 삭제 금지 정책이면 일반 승인을
발급하지 않는다. 등록 토큰과 승인 파일은 발급 직후 한 번만 제공되며
목록에서 다시 조회할 수 없다. 현재 웹 관리자 계정은 모든 중앙 관리 권한을 가진다.

```sh
sudo sentinel-central enrollment-token \
  --state-dir /var/lib/xe-antishell-central \
  --agent-id HOST_ID --output-file /root/xe-enrollment-token --ttl 1h
```

토큰은 한 에이전트에 귀속되며 한 번만 사용할 수 있다. CA 공개 인증서와
토큰은 인증된 별도 경로로 해당 에이전트에 전달한다. CA·정책 개인 키는
전달하지 않는다. 운영자 자격 증명도 파일로 보관하고 명령 인자에 넣지 않는다.
등록, 서명 정책, 조회, 에이전트 삭제 승인과 오프라인 복구 절차는
[Managed v1 운영 문서](devdocs/analysis/managed-v1-operations.md)를 따른다.

## 업그레이드와 데이터 보존

중앙 RPM은 `/usr/sbin/sentinel-central`, 중앙 systemd unit 및 상태
디렉터리만 소유한다. 에이전트 패키지를 요구하거나 에이전트 삭제 승인
명령을 실행하지 않는다. 패키지 삭제는 중앙 서비스만 중지하며 PKI·DB는
삭제하지 않는다. 상태는 별도로 보호하고 백업해야 한다.

SQLite 백업은 서비스를 중지한 일관된 복사 또는 SQLite backup 방식으로
수행한다. 실행 중 `central.db` 하나만 복사하면 WAL의 최근 커밋을 놓칠 수
있다. 상태 디렉터리에는 CA·정책 개인 키와 운영자 자격 증명이 함께 있다.
저장소나 소스 배포물에 실제 상태, 토큰, DB, 호스트 설정을 넣지 않는다.

RPM과 기본 unit은 Rocky/RHEL 계열 9 환경을 기준으로 준비한다. 다른 OS,
별도 호스트 간 통신 및 배포 환경별 검증은 추가로 필요하다. 이 저장소의
자동 테스트 통과는 운영 환경 전체의 검증을 의미하지 않는다.
