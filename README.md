# firewalld 프록시 관리 시스템

A 서버와 B 서버가 방화벽/라우팅 문제로 **직접 통신할 수 없을 때**, 중간에 **프록시 서버**를
두고 firewalld 포트포워딩(DNAT + masquerade)으로 통신을 중계합니다.
이 저장소는 프록시 서버의 **firewalld 정책**, 정책을 적용하는 **스크립트**, 그리고
정책을 쉽게 추가/수정하고 **로그**를 확인하는 **웹 포탈**(OS 인증)을 제공합니다.

```
[A 서버] ──X──> [B 서버]            직접 통신 불가
[A 서버] ──> [프록시(firewalld)] ──> [B 서버]   프록시 중계
```

## 구성

```
Firewalld_mgmt/
├── README.md
├── docs/architecture.md          # 동작 원리 / 아키텍처
├── portal/                       # 웹 포탈 (Flask + PAM)
│   ├── app.py                    # 라우팅/뷰
│   ├── auth.py                   # OS 인증(PAM) + 그룹 정책
│   ├── firewall.py               # firewall-cmd 래퍼 (forward-port/rich rule)
│   ├── models.py                 # SQLite: 규칙/서버/감사로그
│   ├── config.py                 # 환경변수 설정
│   ├── requirements.txt
│   ├── templates/ , static/      # UI
├── scripts/
│   ├── proxy_setup.sh            # 프록시 서버 초기 설정(ip_forward + masquerade)
│   ├── apply_rule.sh             # 규칙 추가 (CLI)
│   ├── remove_rule.sh            # 규칙 제거 (CLI)
│   └── test_connectivity.sh      # A 서버에서 연결 검증
├── systemd/firewalld-portal.service
└── config/rules.example.yaml     # 규칙 예시
```

## 빠른 시작

### 1) 프록시 서버 초기 설정

```bash
sudo ./scripts/proxy_setup.sh public      # zone 기본값 public
```
커널 IP forwarding 과 firewalld masquerade 를 활성화합니다.

### 2) 포탈 설치/실행

```bash
cd portal
python3 -m pip install -r requirements.txt

# 개발 실행 (firewall-cmd 실제 적용)
sudo FWPORTAL_ZONE=public python3 app.py        # http://<프록시IP>:8080

# 적용 없이 화면만 테스트 (firewall-cmd 미실행)
FWPORTAL_DRY_RUN=1 python3 app.py
```

운영 환경은 systemd 사용:
```bash
sudo mkdir -p /opt/firewalld-portal
sudo cp -r . /opt/firewalld-portal/
sudo cp systemd/firewalld-portal.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now firewalld-portal
```

### 3) 로그인

브라우저에서 `http://<프록시IP>:8080` 접속 → **리눅스 OS 계정**으로 로그인.
(특정 그룹만 허용하려면 `FWPORTAL_ALLOWED_GROUPS=wheel` 설정)

### 4) 규칙 추가

포탈 → **프록시 규칙 → + 규칙 추가**:

| 항목 | 설명 | 예시 |
|------|------|------|
| 출발지(A) | 허용할 A 서버 IP/CIDR (비우면 전체 허용) | `10.0.1.10` |
| 수신 포트 | A 가 접속하는 프록시 포트 | `8080` |
| 프로토콜 | tcp / udp | `tcp` |
| 목적지(B) | B 서버 IP | `10.0.2.20` |
| 목적지 포트 | B 서버 포트 | `80` |

저장 즉시 firewalld 에 적용됩니다.

### 5) 검증

A 서버에서:
```bash
./scripts/test_connectivity.sh 10.0.1.100 8080
```

## 실시간 통신 상태 (대시보드)

대시보드 상단의 **실시간 통신 상태** 패널은 각 프록시 규칙의 `A → 프록시 → B` 흐름을
시각적으로 보여주고 **3초마다 자동 갱신**됩니다.

- 흐름이 있는 규칙은 초록색 테두리 + **패킷이 흐르는 애니메이션**으로 표시
- 규칙별 **활성 연결 수**, TCP 상태(ESTABLISHED/TIME_WAIT/SYN_SENT 등), 접속 중인 출발지(A) IP 목록
- 비활성 규칙은 회색/빨간 테두리로 구분
- 데이터 소스는 커널 **연결 추적(conntrack)** — 별도 에이전트 불필요

데이터는 다음 순서로 수집합니다(`portal/monitor.py`):
1. `conntrack -L` (정확, root 권한 필요 — `conntrack-tools` 패키지)
2. `/proc/net/nf_conntrack` (읽기 가능 시)
3. `FWPORTAL_DRY_RUN=1` 데모 모드 — firewalld 없이 합성 데이터로 화면 확인

> 정확한 실시간 집계를 위해 프록시 서버에 conntrack 도구 설치를 권장합니다:
> `dnf install conntrack-tools` 또는 `apt install conntrack`

## CLI 로만 사용 (포탈 없이)

```bash
# A 서버(10.0.1.10) 만 허용하여 8080 -> 10.0.2.20:80 중계
sudo ./scripts/apply_rule.sh -l 8080 -d 10.0.2.20 -p 80 -P tcp -s 10.0.1.10

# 제거
sudo ./scripts/remove_rule.sh -l 8080 -d 10.0.2.20 -p 80 -P tcp -s 10.0.1.10
```

## 주요 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `FWPORTAL_ZONE` | `public` | 규칙을 적용할 firewalld zone |
| `FWPORTAL_PAM_SERVICE` | `login` | PAM 서비스명 (`/etc/pam.d/`) |
| `FWPORTAL_ALLOWED_GROUPS` | (없음) | 로그인 허용 그룹(콤마구분). 비우면 전체 허용 |
| `FWPORTAL_DB` | `/var/lib/firewalld-portal/portal.db` | SQLite 경로 |
| `FWPORTAL_SECRET_KEY` | (랜덤) | 세션 시크릿. 운영 시 고정값 지정 |
| `FWPORTAL_USE_SUDO` | `0` | root 미실행 시 `1` (sudoers 로 firewall-cmd 허용 필요) |
| `FWPORTAL_DRY_RUN` | `0` | `1` 이면 firewall-cmd 미실행(테스트) |
| `FWPORTAL_COOKIE_SECURE` | `0` | HTTPS 사용 시 `1` |

## 로그

- **감사 로그**: 포탈의 모든 작업(로그인/규칙 변경 등)을 SQLite `audit_log` 에 기록, **로그** 메뉴에서 확인.
- **firewalld 시스템 로그**: `journalctl -u firewalld` 를 **로그** 메뉴에서 함께 표시.

## 보안 권장 사항

- 포탈은 **HTTPS(reverse proxy)** 뒤에서 운영하고 `FWPORTAL_COOKIE_SECURE=1` 설정.
- 로그인은 `FWPORTAL_ALLOWED_GROUPS` 로 관리자 그룹만 허용.
- 포탈 접근 포트(예: 8080)는 관리 네트워크로만 제한.
- 동작 원리 상세는 [docs/architecture.md](docs/architecture.md) 참고.
