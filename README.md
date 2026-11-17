# Xe-AntiShell-Central

[Xe-AntiShell](https://github.com/mkjang2000/Xe-AntiShell) 에이전트를 위한
독립 중앙 관리 서비스다. 에이전트 등록, mTLS 이벤트 전송과 ACK, 상태 보고,
서명 정책, 일회용 에이전트 삭제 승인 및 인증서 철회를 제공한다. 프로젝트
코드는 MIT이며, 외부 의존성 고지는 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)에 있다.

중앙 웹 UI, 다중 운영자 권한, 자동 인증서 갱신, PostgreSQL 및 중앙 서버
다중화는 후속 범위다. 에이전트 탐지와 로컬 모니터링 패널은 별도 저장소에서
배포한다. 이 패키지는 중앙 실행 파일 하나와 전용 서비스만 설치한다.

## 빌드와 검증

Linux, Go 1.22 이상, GNU make, Bash, Git, Python 3.9 이상이 필요하다.
검증용 race 테스트에는 C 컴파일러도 필요하다. Go 모듈은 고정 버전으로
다운로드하며, SQLite는 `modernc.org/sqlite`의 pure Go 드라이버를 사용한다.
공용 계약은 `github.com/mkjang2000/Xe-AntiShell/protocol v0.1.0`에 고정한다.

```sh
make verify
make static
./build/sentinel-central version
```

`make verify`는 소스·문서 검사, shell/패키징 회귀 검사, 형식 검사,
`go vet`, race 테스트와 정적 실행 파일 빌드를 수행한다. 구조는
[Project_tree.md](Project_tree.md)에 정리되어 있다.

## 설치

RPM 빌드에는 `rpm`, `rpmbuild`, systemd RPM 매크로와 GNU tar가 추가로
필요하다. 빌드는 임시 디렉터리에서 수행하며 호스트 패키지를 설치하지 않는다.
출력은 기본 `dist/rpm/`이다. 동일 파일 덮어쓰기는 `--force`로 명시한다.

```sh
make rpm
sudo ./install.sh --rpm dist/rpm/xe-antishell-central-0.1.0-1.el9.x86_64.rpm
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
