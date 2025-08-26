#!/usr/bin/env bash
# =============================================================================
# OAI 5GC 통합 디버깅 스크립트 (Host 실행용)
#   - docker-compose 기반 OAI 5GC 배포 환경 점검 자동화
#   - HTTP/2 (SBI), PFCP, GTP-U, NGAP 주요 포트/로그 확인
#   - 컨테이너 내부 도구 없어도 Host 기준으로 확인 가능
#
# 사용법:
#   chmod +x debug-5gc-host.sh
#   ./debug-5gc-host.sh | tee debug-$(date +%F-%H%M).log
# =============================================================================

set -euo pipefail

# ---------- 색상 ----------
G="\033[0;32m"; Y="\033[1;33m"; R="\033[0;31m"; N="\033[0m"
ok(){ echo -e "${G}[OK]${N}  $*"; }
ng(){ echo -e "${R}[NG]${N}  $*"; }
wn(){ echo -e "${Y}[WARN]${N} $*"; }
hr(){ printf '%*s\n' "${COLUMNS:-100}" '' | tr ' ' '='; }

# ---------- 환경 변수 ----------
BR_NET="demo-oai-public-net"   # docker network name
BR_IF="demo-oai"               # linux bridge interface name
NFS=(oai-nrf oai-amf oai-smf oai-upf oai-udr oai-udm oai-ausf mysql oai-ext-dn)

PORT_SBI=${PORT_SBI:-8080}         # HTTP/2 SBI
PORT_HTTP1=${PORT_HTTP1:-80}       # HTTP/1 SBI
PORT_METRICS=${PORT_METRICS:-9090} # Prometheus
PORT_N2_SCTP=${PORT_N2_SCTP:-38412}
PORT_N4_PFCP=${PORT_N4_PFCP:-8805}
PORT_GTPU=${PORT_GTPU:-2152}

# curl 옵션을 bash 배열로 유지
CURL_H2_OPTS=( -sS --http2-prior-knowledge )

# ---------- 0. 네트워크/브리지 ----------
hr
echo "========== [0. 네트워크/브리지 상태] =========="
if docker network inspect "$BR_NET" >/dev/null 2>&1; then
  ok "Docker 네트워크 존재: $BR_NET"
else
  ng "Docker 네트워크 없음: $BR_NET"
fi

if ip link show "$BR_IF" >/dev/null 2>&1; then
  ok "브리지 인터페이스: $BR_IF"
else
  ng "브리지 인터페이스 없음: $BR_IF"
fi

# ---------- 1. 컨테이너 상태 ----------
hr
echo "========== [1. 컨테이너 상태/헬스] =========="
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | sort

# ---------- 2. NF IP 수집 ----------
hr
echo "========== [2. IP 수집] =========="
declare -A IPMAP=()
for name in "${NFS[@]}"; do
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null || true)
  if [[ -n "${ip}" ]]; then
    IPMAP[$name]="$ip"
    ok "$name IP: $ip"
  else
    wn "$name IP 조회 실패"
  fi
done

NRF_IP="${IPMAP[oai-nrf]:-}"
AMF_IP="${IPMAP[oai-amf]:-}"
SMF_IP="${IPMAP[oai-smf]:-}"
UPF_IP="${IPMAP[oai-upf]:-}"

# ---------- 3. AMF -> NRF 이름해결 ----------
hr
echo "========== [3. FQDN 확인: AMF -> oai-nrf] =========="
if docker exec -it oai-amf getent hosts oai-nrf >/dev/null 2>&1; then
  docker exec -it oai-amf getent hosts oai-nrf
  ok "AMF에서 oai-nrf 이름해결 성공"
else
  ng "AMF에서 oai-nrf 이름해결 실패"
fi

# ---------- 4. NRF REST API (HTTP/2) ----------
hr
echo "========== [4. NRF API 질의] =========="
if [[ -n "$NRF_IP" ]]; then
  for t in AMF SMF UPF; do
    url="http://${NRF_IP}:${PORT_SBI}/nnrf-nfm/v1/nf-instances?nf-type=${t}"
    echo "[*] ${t} 조회: $url"
    code=$(curl -s -o /tmp/nrf_${t}.json -w '%{http_code}' "${CURL_H2_OPTS[@]}" "$url" || echo "000")
    if [[ "$code" == "200" ]]; then
      ok "NRF 응답 코드 200 (${t})"
      jq '.' /tmp/nrf_${t}.json | head -n 5
    else
      ng "NRF 응답 실패 (${t}) code=${code}"
    fi
  done
else
  ng "NRF IP 없음 → API 질의 불가"
fi

# ---------- 5. 로그 ----------
hr
echo "========== [5. 로그 요약] =========="
echo "-- NRF 로그 --"
docker logs --tail=50 oai-nrf 2>/dev/null | egrep -i 'Handle|HTTP|error|fail' || true

echo "-- SMF 로그 --"
docker logs --tail=50 oai-smf 2>/dev/null | egrep -i 'PFCP|HEARTBEAT|error|fail' || true

echo "-- UPF 로그 --"
docker logs --tail=50 oai-upf 2>/dev/null | egrep -i 'HEARTBEAT|PFCP|error|fail' || true

# ---------- 6. 포트 리스닝 ----------
hr
echo "========== [6. 포트 리스닝 상태] =========="
echo "-- UPF (UDP) --"
docker exec -it oai-upf sh -lc "ss -lun 2>/dev/null | grep -E ':${PORT_N4_PFCP}|:${PORT_GTPU}' || true"

echo "-- AMF (SCTP) --"
docker exec -it oai-amf sh -lc "ss -lpn 2>/dev/null | grep sctp || true"

# ---------- 7. 연결성 ----------
hr
echo "========== [7. 연결성 빠른 체크] =========="
if [[ -n "$NRF_IP" ]]; then
  if timeout 2 bash -lc "cat < /dev/null > /dev/tcp/${NRF_IP}/${PORT_SBI}" 2>/dev/null; then
    ok "Host→NRF TCP ${PORT_SBI} 접속 가능"
  else
    ng "Host→NRF TCP ${PORT_SBI} 접속 실패"
  fi
else
  ng "NRF IP 없음"
fi

echo "※ UDP/N3/N4는 tcpdump로 확인 필요:"
echo "  sudo tcpdump -i ${BR_IF} 'udp port ${PORT_N4_PFCP} or udp port ${PORT_GTPU}' -c 20 -vv"

hr
echo "========== [완료] =========="
echo "[*] ./$(basename "$0") | tee debug-$(date +%F-%H%M).log"

#./debug-5gc-host.sh | tee debug-$(date +%F-%H%M).log 로 실행권장
