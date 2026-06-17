#!/usr/bin/env bash
#
# remove_rule.sh
# 프록시 서버에서 포트포워딩 규칙 한 건을 제거합니다.
#
# 사용법:
#   sudo ./remove_rule.sh -l <수신포트> -d <B서버IP> -p <목적지포트> \
#                         [-P tcp|udp] [-s <A서버IP/CIDR>] [-z <zone>]
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

if [[ -n "$SRC" ]]; then
  RULE="rule family=\"ipv4\" source address=\"$SRC\" forward-port port=\"$LISTEN\" protocol=\"$PROTO\" to-port=\"$DPORT\" to-addr=\"$DEST\""
  firewall-cmd --permanent --zone="$ZONE" --remove-rich-rule="$RULE"
else
  SPEC="port=$LISTEN:proto=$PROTO:toport=$DPORT:toaddr=$DEST"
  firewall-cmd --permanent --zone="$ZONE" --remove-forward-port="$SPEC"
fi

firewall-cmd --reload
echo "제거 완료. (zone=$ZONE)"
