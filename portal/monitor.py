"""
실시간 통신 상태 모니터링 모듈.

firewalld 포트포워딩은 커널 netfilter 의 DNAT 로 동작하므로, 로컬 소켓이 아닌
**연결 추적(conntrack)** 정보를 읽어 각 프록시 규칙(A -> 프록시 -> B)의 실시간
연결 상태를 집계합니다.

데이터 소스 우선순위:
  1) `conntrack -L`  (root 권한 필요, 가장 정확)
  2) `/proc/net/nf_conntrack`  (읽기 가능 시)
  3) DRY_RUN(데모) 모드면 합성 데이터 생성 (firewalld 없이 화면 확인용)

규칙 매칭 기준:
  - proto 일치
  - 원본(original) 방향의 dport == listen_port  (A 가 프록시로 접속한 포트)
  - 응답(reply) 방향의 src == dest_addr        (DNAT 로 B 로 전달되었음을 확인)
"""
import random
import subprocess
import time

from config import Config

# TCP conntrack 상태값
_TCP_STATES = {
    "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT",
    "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "NONE",
}


def _parse_line(line):
    """conntrack / nf_conntrack 한 줄을 파싱하여 dict 반환 (실패 시 None)."""
    tokens = line.split()
    if not tokens:
        return None
    proto = None
    for t in tokens:
        if t in ("tcp", "udp", "sctp", "dccp"):
            proto = t
            break
    if proto is None:
        return None

    state = ""
    for t in tokens:
        if t in _TCP_STATES:
            state = t
            break
    if not state and proto == "udp":
        state = "UNREPLIED" if "[UNREPLIED]" in line else "ASSURED"

    # key=value 쌍을 순서대로 수집 (원본 튜플 -> 응답 튜플 순으로 두 번 등장)
    src, dst, sport, dport = [], [], [], []
    for t in tokens:
        if "=" not in t:
            continue
        k, _, v = t.partition("=")
        if k == "src":
            src.append(v)
        elif k == "dst":
            dst.append(v)
        elif k == "sport":
            sport.append(v)
        elif k == "dport":
            dport.append(v)

    if not src or not dport:
        return None

    def _get(lst, idx):
        return lst[idx] if len(lst) > idx else None

    return {
        "proto": proto,
        "state": state or "ESTABLISHED",
        "orig_src": _get(src, 0),
        "orig_dst": _get(dst, 0),
        "orig_dport": _get(dport, 0),
        "reply_src": _get(src, 1),
        "reply_sport": _get(sport, 1),
    }


def _read_conntrack():
    """현재 연결 목록을 파싱하여 반환. (entries, source 문자열)"""
    # 1) conntrack -L
    try:
        proc = subprocess.run(
            ["conntrack", "-L"], capture_output=True, text=True, timeout=8
        )
        if proc.returncode == 0:
            entries = [e for e in (_parse_line(l) for l in proc.stdout.splitlines()) if e]
            return entries, "conntrack"
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass
    except Exception:  # noqa: BLE001
        pass

    # 2) /proc/net/nf_conntrack
    try:
        with open("/proc/net/nf_conntrack", "r") as f:
            entries = [e for e in (_parse_line(l) for l in f) if e]
            return entries, "nf_conntrack"
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return None, "none"


def _match(entry, rule):
    """conntrack 엔트리가 규칙에 해당하는지 판별."""
    if entry["proto"] != rule["protocol"]:
        return False
    try:
        if int(entry["orig_dport"]) != int(rule["listen_port"]):
            return False
    except (TypeError, ValueError):
        return False
    # 응답 src 가 DNAT 대상(B)와 일치하면 확실한 매칭
    if entry.get("reply_src"):
        return entry["reply_src"] == rule["dest_addr"]
    # 응답 정보가 없으면 포트+프로토콜만으로 매칭(차선)
    return True


def _demo_stats(rule):
    """DRY_RUN 데모: 규칙별 합성 실시간 데이터 생성."""
    if not rule.get("enabled"):
        return {"active": 0, "states": {}, "sources": []}
    # 규칙 id 기반 시드 + 시간으로 매 갱신마다 약간씩 변동
    rnd = random.Random(f"{rule['id']}-{int(time.time() // 3)}")
    active = rnd.choice([0, 0, 1, 2, 3, 4, 5, 8])
    base = rule.get("source_addr") or "10.0.1."
    if "/" in base or base.count(".") < 3:
        base_prefix = base.split("/")[0].rsplit(".", 1)[0] if base else "10.0.1"
        if not base_prefix or base_prefix.count(".") != 2:
            base_prefix = "10.0.1"
        sources = {}
        for _ in range(active):
            ip = f"{base_prefix}.{rnd.randint(10, 60)}"
            sources[ip] = sources.get(ip, 0) + 1
    else:
        sources = {base: active} if active else {}
    states = {}
    for _ in range(active):
        st = rnd.choice(["ESTABLISHED", "ESTABLISHED", "ESTABLISHED", "TIME_WAIT", "SYN_SENT"])
        states[st] = states.get(st, 0) + 1
    return {
        "active": active,
        "states": states,
        "sources": [{"ip": k, "count": v} for k, v in sorted(sources.items())],
    }


def get_live_stats(rules):
    """
    규칙 목록에 대한 실시간 통신 상태 집계 반환.
    """
    # DRY_RUN(데모) 모드에서는 실제 프록시가 없으므로 항상 합성 데이터 사용
    if Config.DRY_RUN:
        entries, source, use_demo = None, "demo", True
    else:
        entries, source = _read_conntrack()
        use_demo = False

    result_rules = []
    total_active = 0

    for rule in rules:
        if use_demo:
            stats = _demo_stats(rule)
        elif entries is None:
            stats = {"active": 0, "states": {}, "sources": []}
        else:
            matched = [e for e in entries if rule.get("enabled") and _match(e, rule)]
            states = {}
            sources = {}
            for e in matched:
                states[e["state"]] = states.get(e["state"], 0) + 1
                s = e["orig_src"] or "?"
                sources[s] = sources.get(s, 0) + 1
            stats = {
                "active": len(matched),
                "states": states,
                "sources": [{"ip": k, "count": v}
                            for k, v in sorted(sources.items(), key=lambda x: -x[1])],
            }

        if not rule.get("enabled"):
            status = "disabled"
        elif stats["active"] > 0:
            status = "active"
        else:
            status = "idle"

        total_active += stats["active"]
        result_rules.append({
            "id": rule["id"],
            "name": rule["name"],
            "protocol": rule["protocol"],
            "listen_port": rule["listen_port"],
            "dest_addr": rule["dest_addr"],
            "dest_port": rule["dest_port"],
            "source_addr": rule.get("source_addr") or "any",
            "enabled": bool(rule.get("enabled")),
            "status": status,
            "active": stats["active"],
            "states": stats["states"],
            "sources": stats["sources"][:5],
        })

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "demo" if use_demo else source,
        "total_active": total_active,
        "active_rules": sum(1 for r in result_rules if r["status"] == "active"),
        "rules": result_rules,
    }
