#!/usr/bin/env bash
#
# apply_rule.sh
# 프록시 서버에 포트포워딩 규칙 한 건을 추가합니다 (CLI, 포탈 없이도 사용 가능).
#
# 사용법:
#   sudo ./apply_rule.sh -l <수신포트> -d <B서버IP> -p <목적지포트> \
#                        [-P tcp|udp] [-s <A서버IP/CIDR>] [-z <zone>]
#
# 예시 (모든 출발지 허용):
#   sudo ./apply_rule.sh -l 8080 -d 10.0.2.20 -p 80 -P tcp
#
# 예시 (A 서버만 허용 - rich rule):
#   sudo ./apply_rule.sh -l 8080 -d 10.0.2.20 -p 80 -P tcp -s 10.0.1.10
#
set -euo pipefail

ZONE="public"; PROTO="tcp"; SRC=""; LISTEN=""; DEST=""; DPORT=""

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "l:d:p:P:s:z:h" opt; do
  case "$opt" in
    l) LISTEN="$OPTARG" ;;
    d) DEST="$OPTARG" ;;
    p) DPORT="$OPTARG" ;;
    P) PROTO="$OPTARG" ;;
    s) SRC="$OPTARG" ;;
    z) ZONE="$OPTARG" ;;
    *) usage ;;
  esac
done

[[ -z "$LISTEN" || -z "$DEST" || -z "$DPORT" ]] && usage
[[ $EUID -ne 0 ]] && { echo "root 권한으로 실행하세요." >&2; exit 1; }

# masquerade 보장
if [[ "$(firewall-cmd --permanent --zone="$ZONE" --query-masquerade)" != "yes" ]]; then
  firewall-cmd --permanent --zone="$ZONE" --add-masquerade
fi

if [[ -n "$SRC" ]]; then
  RULE="rule family=\"ipv4\" source address=\"$SRC\" forward-port port=\"$LISTEN\" protocol=\"$PROTO\" to-port=\"$DPORT\" to-addr=\"$DEST\""
  echo "rich rule 추가: $RULE"
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$RULE"
else
  SPEC="port=$LISTEN:proto=$PROTO:toport=$DPORT:toaddr=$DEST"
  echo "forward-port 추가: $SPEC"
  firewall-cmd --permanent --zone="$ZONE" --add-forward-port="$SPEC"
fi

firewall-cmd --reload
echo "적용 완료. (zone=$ZONE)"
