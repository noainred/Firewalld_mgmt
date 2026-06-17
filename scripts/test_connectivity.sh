#!/usr/bin/env bash
#
# test_connectivity.sh
# A 서버에서 실행하여 프록시를 통해 B 서버까지 통신이 되는지 검증합니다.
#
# 사용법: ./test_connectivity.sh <프록시IP> <수신포트>
# 예시:   ./test_connectivity.sh 10.0.1.100 8080
#
set -euo pipefail

PROXY="${1:?프록시 IP 를 입력하세요}"
PORT="${2:?수신 포트를 입력하세요}"

echo "[*] A 서버 -> 프록시(${PROXY}:${PORT}) -> B 서버 통신 테스트"

if command -v nc >/dev/null 2>&1; then
  if nc -z -w 5 "$PROXY" "$PORT"; then
    echo "[OK] TCP ${PROXY}:${PORT} 연결 성공 (프록시 포워딩 동작)"
  else
    echo "[FAIL] TCP ${PROXY}:${PORT} 연결 실패"
    echo "       확인: 프록시 masquerade/forward-port, B 서버 방화벽, 커널 ip_forward"
    exit 1
  fi
else
  echo "nc(netcat) 미설치 - /dev/tcp 로 시도"
  if timeout 5 bash -c "cat < /dev/null > /dev/tcp/${PROXY}/${PORT}" 2>/dev/null; then
    echo "[OK] 연결 성공"
  else
    echo "[FAIL] 연결 실패"; exit 1
  fi
fi

# B 서버가 HTTP 라면 응답도 확인
if command -v curl >/dev/null 2>&1; then
  echo "[*] HTTP 응답 확인 (선택):"
  curl -sS -m 5 "http://${PROXY}:${PORT}/" -o /dev/null -w "    HTTP status: %{http_code}\n" || true
fi
