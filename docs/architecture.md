# 아키텍처 / 동작 원리

## 1. 문제 상황

A 서버와 B 서버가 통신해야 하지만, 방화벽 또는 라우팅 문제로 **직접 통신이 불가능**한 경우가 있습니다.

```
[A 서버] ──X──> [B 서버]      (직접 경로 차단/라우팅 없음)
```

두 서버 모두에서 접근 가능한 **프록시 서버**를 중간에 두어 통신을 중계합니다.

```
[A 서버] ──> [프록시 서버] ──> [B 서버]
```

## 2. firewalld 포워딩 방식

프록시 서버는 firewalld 의 **forward-port (DNAT)** 와 **masquerade (SNAT)** 기능으로
L4 포트포워딩을 수행합니다. 별도 프록시 데몬(nginx/haproxy) 없이 커널 netfilter 만으로 동작합니다.

| 단계 | 설명 |
|------|------|
| 1. A → 프록시 | A 서버가 `프록시:listen_port` 로 접속 |
| 2. DNAT | firewalld forward-port 가 목적지를 `B:dest_port` 로 변경 |
| 3. masquerade | 출발지를 프록시 IP 로 변경(SNAT) → B 의 응답이 프록시로 돌아옴 |
| 4. 역경로 | 프록시가 응답을 A 로 그대로 반환 |

### 필수 전제

1. 커널 IP forwarding: `net.ipv4.ip_forward = 1` (`proxy_setup.sh` 가 설정)
2. zone 에 masquerade 활성화
3. forward-port 규칙(또는 출발지 제한 시 rich rule)

### 규칙 두 가지 형태

- **출발지 무제한** → 일반 forward-port
  ```
  firewall-cmd --permanent --zone=public \
    --add-forward-port=port=8080:proto=tcp:toport=80:toaddr=10.0.2.20
  ```
- **출발지 제한(A 서버만 허용)** → rich rule
  ```
  firewall-cmd --permanent --zone=public --add-rich-rule='
    rule family="ipv4" source address="10.0.1.10"
    forward-port port="8080" protocol="tcp" to-port="80" to-addr="10.0.2.20"'
  ```

## 3. 구성 요소

```
┌──────────────────────────────────────────────────────────┐
│                      프록시 서버                            │
│                                                            │
│  ┌──────────────┐   firewall-cmd    ┌──────────────────┐  │
│  │  웹 포탈      │ ────────────────> │   firewalld      │  │
│  │  (Flask)     │                   │ forward-port +    │  │
│  │  PAM 인증     │ <──── 상태조회 ──── │ masquerade        │  │
│  └──────┬───────┘                   └──────────────────┘  │
│         │ 규칙/감사로그                                      │
│  ┌──────▼───────┐                                          │
│  │  SQLite DB   │  proxy_rules / servers / audit_log        │
│  └──────────────┘                                          │
└──────────────────────────────────────────────────────────┘
```

- **웹 포탈**: 규칙 CRUD, 서버 인벤토리, 로그 조회. OS 계정(PAM) 인증.
- **firewalld**: 실제 패킷 포워딩 수행.
- **SQLite**: 규칙의 "원본(source of truth)" + 감사 로그. 포탈이 DB → firewalld 로 동기화.

## 4. 인증 (OS 인증)

- 포탈 로그인은 리눅스 OS 계정/비밀번호를 **PAM** 으로 검증합니다 (`python-pam`).
- PAM 서비스는 `FWPORTAL_PAM_SERVICE`(기본 `login`) 로 지정합니다.
- `FWPORTAL_ALLOWED_GROUPS` 로 특정 그룹(예: `wheel`)만 로그인 허용 가능.
- PAM 이 shadow 를 읽으려면 포탈 프로세스가 root 권한이어야 합니다(systemd unit 은 root 실행).

## 5. 데이터 흐름 (규칙 추가)

1. 사용자가 포탈에서 규칙 입력 → 유효성 검증(IP/포트/프로토콜)
2. SQLite `proxy_rules` 에 저장
3. `firewall.apply_rule()` → `firewall-cmd --permanent ... --reload`
4. `audit_log` 에 작업자/내용/결과 기록
5. 대시보드에서 firewalld 런타임 상태로 검증
