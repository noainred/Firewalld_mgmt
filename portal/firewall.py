"""
firewalld 프록시(포트 포워딩) 관리 래퍼.

이 프록시 서버는 A 서버 -> (프록시) -> B 서버 통신을 중계합니다.
firewalld 의 forward-port(DNAT) + masquerade(SNAT) 를 사용하여,
A 서버가 프록시의 listen_port 로 접속하면 트래픽이 B 서버(dest_addr:dest_port)
로 전달되고 응답이 다시 A 서버로 돌아갑니다.

규칙에 source(A 서버 IP) 가 지정되면 rich rule 을 사용하여 해당 출발지만
허용하고, 지정되지 않으면 일반 forward-port 를 사용합니다.

모든 변경은 --permanent 로 적용한 뒤 reload 합니다.
"""
import shlex
import subprocess

from config import Config


class FirewallError(Exception):
    pass


def _base_cmd():
    cmd = []
    if Config.USE_SUDO:
        cmd += ["sudo", "-n"]
    cmd += ["firewall-cmd"]
    return cmd


def _run(args, check=True):
    """firewall-cmd 명령을 실행하고 (rc, stdout, stderr) 반환."""
    cmd = _base_cmd() + args
    printable = " ".join(shlex.quote(c) for c in cmd)
    if Config.DRY_RUN:
        return 0, f"[DRY_RUN] {printable}", ""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        raise FirewallError("firewall-cmd 를 찾을 수 없습니다. firewalld 가 설치되어 있나요?")
    except subprocess.TimeoutExpired:
        raise FirewallError(f"명령 시간 초과: {printable}")
    if check and proc.returncode != 0:
        raise FirewallError(
            f"명령 실패 ({proc.returncode}): {printable}\n{proc.stderr.strip()}"
        )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _rich_rule(rule):
    """source 가 지정된 규칙의 rich rule 문자열 생성."""
    return (
        f'rule family="ipv4" '
        f'source address="{rule["source_addr"]}" '
        f'forward-port port="{rule["listen_port"]}" '
        f'protocol="{rule["protocol"]}" '
        f'to-port="{rule["dest_port"]}" '
        f'to-addr="{rule["dest_addr"]}"'
    )


def _forward_port_spec(rule):
    """source 가 없는 규칙의 forward-port 스펙 생성."""
    return (
        f'port={rule["listen_port"]}:proto={rule["protocol"]}:'
        f'toport={rule["dest_port"]}:toaddr={rule["dest_addr"]}'
    )


def ensure_prerequisites():
    """포워딩에 필요한 masquerade 활성화. (IP forwarding 은 OS 커널 설정)"""
    zone = Config.FIREWALL_ZONE
    rc, out, _ = _run(
        ["--permanent", f"--zone={zone}", "--query-masquerade"], check=False
    )
    if out != "yes":
        _run(["--permanent", f"--zone={zone}", "--add-masquerade"])
    return True


def apply_rule(rule):
    """규칙 한 건을 firewalld 영구 설정에 추가하고 reload."""
    zone = Config.FIREWALL_ZONE
    ensure_prerequisites()
    if rule.get("source_addr"):
        _run(["--permanent", f"--zone={zone}",
              f"--add-rich-rule={_rich_rule(rule)}"])
    else:
        _run(["--permanent", f"--zone={zone}",
              f"--add-forward-port={_forward_port_spec(rule)}"])
    reload()
    return True


def remove_rule(rule):
    """규칙 한 건을 firewalld 영구 설정에서 제거하고 reload."""
    zone = Config.FIREWALL_ZONE
    if rule.get("source_addr"):
        _run(["--permanent", f"--zone={zone}",
              f"--remove-rich-rule={_rich_rule(rule)}"], check=False)
    else:
        _run(["--permanent", f"--zone={zone}",
              f"--remove-forward-port={_forward_port_spec(rule)}"], check=False)
    reload()
    return True


def reload():
    _run(["--reload"])
    return True


def runtime_status():
    """현재 zone 의 forward-port / rich rule / masquerade 상태 조회."""
    zone = Config.FIREWALL_ZONE
    _, fwd, _ = _run([f"--zone={zone}", "--list-forward-ports"], check=False)
    _, rich, _ = _run([f"--zone={zone}", "--list-rich-rules"], check=False)
    _, masq, _ = _run([f"--zone={zone}", "--query-masquerade"], check=False)
    return {
        "zone": zone,
        "forward_ports": [l for l in fwd.splitlines() if l.strip()],
        "rich_rules": [l for l in rich.splitlines() if l.strip()],
        "masquerade": masq == "yes",
    }


def sync_all(rules):
    """DB 의 모든 활성 규칙을 firewalld 에 일괄 재적용."""
    ensure_prerequisites()
    zone = Config.FIREWALL_ZONE
    for rule in rules:
        if not rule.get("enabled", 1):
            continue
        if rule.get("source_addr"):
            _run(["--permanent", f"--zone={zone}",
                  f"--add-rich-rule={_rich_rule(rule)}"], check=False)
        else:
            _run(["--permanent", f"--zone={zone}",
                  f"--add-forward-port={_forward_port_spec(rule)}"], check=False)
    reload()
    return True
