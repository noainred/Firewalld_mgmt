#!/usr/bin/env bash
#
# proxy_setup.sh
# 프록시 서버 초기 설정 스크립트.
# A 서버 -> (프록시) -> B 서버 포트포워딩을 위해 필요한
# 커널 IP forwarding 활성화 + firewalld masquerade 설정을 수행합니다.
#
# 사용법: sudo ./proxy_setup.sh [zone]
#
set -euo pipefail

ZONE="${1:-public}"

if [[ $EUID -ne 0 ]]; then
  echo "root 권한으로 실행하세요 (sudo)." >&2
  exit 1
fi

echo "[1/4] 커널 IPv4 forwarding 활성화..."
# 영구 적용
cat > /etc/sysctl.d/99-firewalld-proxy.conf <<'EOF'
# firewalld 프록시(포트포워딩)용 IP forwarding
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null
echo "    net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"

echo "[2/4] firewalld 설치/구동 확인..."
if ! command -v firewall-cmd >/dev/null 2>&1; then
  echo "firewalld 가 설치되어 있지 않습니다. (dnf/apt install firewalld)" >&2
  exit 1
fi
systemctl enable --now firewalld

echo "[3/4] zone '${ZONE}' 에 masquerade 활성화..."
if [[ "$(firewall-cmd --permanent --zone="${ZONE}" --query-masquerade)" != "yes" ]]; then
  firewall-cmd --permanent --zone="${ZONE}" --add-masquerade
fi

echo "[4/4] 설정 reload..."
firewall-cmd --reload

echo
echo "완료. 현재 zone '${ZONE}' 상태:"
firewall-cmd --zone="${ZONE}" --list-all
echo
echo "이제 포탈 또는 apply_rule.sh 로 포워딩 규칙을 추가하세요."
