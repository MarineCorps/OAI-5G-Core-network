#!/usr/bin/env bash
# OAI 5GC 통합 디버깅 스크립트 (Scenario 1 / HTTP/2(h2c) 기본)
# 사용법:
#   ./debug-5gc-extended.sh                # 표준 점검
#   ./debug-5gc-extended.sh --tcpdump      # tcpdump로 짧게 패킷 캡처 추가(루트 필요)
#   ./debug-5gc-extended.sh --http1        # HTTP/1 강제 테스트 (conf가 http_version:1일 때)
#   ./debug-5gc-extended.sh --pcap /tmp/5gc.pcap   # 캡처 파일 경로 지정
#   ./debug-5gc-extended.sh --net demo-oai-public-net  # 네트워크 이름 변경
#
# 로그 저장:
#   ./debug-5gc-extended.sh | tee debug-$(date +%F-%H%M).log

set -u  # 미정의 변수 에러
set -o pipefail

# 기본 옵션
DO_TCPDUMP=0
FORCE_HTTP1=0
PCAP_PATH="/tmp/5gc-diag-$(date +%s).pcap"
NET="demo-oai-public-net"
BR_IF="demo-oai"
CURL_IMG="curlimages/curl:8.8.0"
NETTOOLS_IMG="nicolaka/netshoot"

pass() { echo -e "[OK]  $*"; }
fail() { echo -e "[!!] $*"; }
info() { echo -e "[*]  $*"; }

# -------- 옵션 파싱 --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tcpdump) DO_TCPDUMP=1; shift ;;
    --http1)   FORCE_HTTP1=1; shift ;;
    --pcap)    PCAP_PATH="$2"; shift 2 ;;
    --net)     NET="$2"; shift 2 ;;
    *) info "알 수 없는 옵션: $1"; shift ;;
  esac
done

# -------- 기본 환경/요구툴 체크 --------
if ! command -v docker >/dev/null 2>&1; then
  fail "docker 명령을 찾을 수 없습니다."
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  fail "jq가 필요합니다. (sudo apt install -y jq)"
fi
if [[ $DO_TCPDUMP -eq 1 ]] && ! command -v tcpdump >/dev/null 2>&1; then
  fail "tcpdump가 필요합니다. (sudo apt install -y tcpdump)"
  DO_TCPDUMP=0
fi

# -------- 공통 함수 --------
container_ip () {
  local name="$1"
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null
}

curl_h2c () {
  # HTTP/2(h2c) curl (curl 컨테이너로 실행)
  local url="$1"
  docker run --rm --network "$NET" "$CURL_IMG" \
    -sS -v --http2-prior-knowledge -H 'Accept: application/json' "$url"
}

curl_h1 () {
  # HTTP/1 curl (curl 컨테이너로 실행)
  local url="$1"
  docker run --rm --network "$NET" "$CURL_IMG" \
    -sS -v -H 'Accept: application/json' "$url"
}

ss_listen_in_container () {
  # 컨테이너 네임스페이스에서 ss 실행 (netshoot 사용)
  local cname="$1"
  docker run --rm --network "container:${cname}" "$NETTOOLS_IMG" \
    ss -ltnp 2>/dev/null || true
}

# -------- 0) 브리지/네트워크 --------
echo "========== [0. 네트워크/브리지 상태] =========="
if docker network inspect "$NET" >/dev/null 2>&1; then
  pass "Docker 네트워크 존재: $NET"
else
  fail "Docker 네트워크가 없습니다: $NET"
fi
# 브리지 인터페이스 이름 추정 (compose에 driver_opts로 demo-oai를 쓰는 경우)
if ip link show "$BR_IF" >/dev/null 2>&1; then
  pass "브리지 인터페이스: $BR_IF"
else
  info "브리지 인터페이스($BR_IF)를 찾지 못했습니다. tcpdump는 건너뜁니다."
  DO_TCPDUMP=0
fi

echo
echo "========== [1. 컨테이너 상태/헬스] =========="
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

# -------- 2) 핵심 컨테이너 IP 수집 --------
echo
echo "========== [2. IP 수집] =========="
declare -A IP
for c in oai-nrf oai-amf oai-smf oai-upf oai-udr oai-udm oai-ausf mysql oai-ext-dn; do
  ip=$(container_ip "$c")
  if [[ -n "${ip}" ]]; then
    IP[$c]="$ip"
    pass "$c IP: ${ip}"
  else
    info "$c IP: (미실행/미할당)"
  fi
done

# -------- 3) DNS/FQDN 확인 (컨테이너 내부 이름해결) --------
echo
echo "========== [3. FQDN 확인: AMF -> oai-nrf] =========="
if docker exec -it oai-amf getent hosts oai-nrf >/dev/null 2>&1; then
  docker exec -it oai-amf getent hosts oai-nrf
  pass "AMF에서 oai-nrf 이름해결 성공"
else
  fail "AMF 컨테이너 내 FQDN(oai-nrf) 확인 실패"
fi

# -------- 4) NRF API 질의 (HTTP/2 기본, 필요 시 HTTP/1) --------
echo
echo "========== [4. NRF API 질의] =========="
NRF_URL_IP="http://${IP[oai-nrf]:-127.0.0.1}:8080/nnrf-nfm/v1/nf-instances?nf-type=AMF"
info "테스트 URL: $NRF_URL_IP"

if [[ $FORCE_HTTP1 -eq 1 ]]; then
  RESP=$(curl_h1 "$NRF_URL_IP" 2>&1)
else
  RESP=$(curl_h2c "$NRF_URL_IP" 2>&1)
fi

HTTP_CODE=$(printf "%s" "$RESP" | grep -m1 -E '< HTTP/' | awk '{print $3}' || true)
BODY=$(printf "%s" "$RESP" | sed -n '/^{/,$p' || true)

if [[ "$HTTP_CODE" == "200" ]]; then
  pass "NRF 응답 코드 200"
  if command -v jq >/dev/null 2>&1; then
    printf "%s\n" "$BODY" | jq . 2>/dev/null || printf "%s\n" "$BODY"
  else
    printf "%s\n" "$BODY"
  fi
else
  fail "NRF 응답 비정상 (code=${HTTP_CODE:-N/A}). 원문:"
  echo "$RESP" | sed -n '1,60p'
fi

# -------- 5) NRF 로그 (등록/조회 동작) --------
echo
echo "========== [5. NRF 로그 (등록/조회)] =========="
docker logs --tail=200 oai-nrf 2>/dev/null | egrep -i \
'Handle Update NF Instance|Retrieve a collection|HTTP version 2|error|fail' || info "NRF 로그 없음/매칭 없음"

# -------- 6) SMF↔UPF PFCP 연결 --------
echo
echo "========== [6. SMF↔UPF PFCP] =========="
docker logs --tail=200 oai-smf 2>/dev/null | egrep -i \
'ASSOCIATION SETUP RESPONSE|PFCP HEARTBEAT|error|fail' || info "SMF 로그에서 매칭 없음"
docker logs --tail=200 oai-upf 2>/dev/null | egrep -i \
'HEARTBEAT REQUEST|HEARTBEAT RESPONSE|error|fail' || info "UPF 로그에서 매칭 없음"

# -------- 7) 포트 리스닝 상태 (컨테이너 네임스페이스) --------
echo
echo "========== [7. 포트 리스닝 상태] =========="
for c in oai-nrf oai-amf oai-smf oai-upf; do
  echo "-- ${c} --"
  if docker ps --format '{{.Names}}' | grep -qx "$c"; then
    ss_listen_in_container "$c" | grep -E ':80|:8080|:9090|:38412' || info "리스닝 정보 매칭 없음(정상일 수도 있음)"
  else
    info "$c 컨테이너가 실행 중이 아님"
  fi
done

# -------- 8) (선택) tcpdump로 짧은 캡처 --------
if [[ $DO_TCPDUMP -eq 1 ]]; then
  echo
  echo "========== [8. tcpdump 캡처 (브리지: ${BR_IF})] =========="
  if [[ $EUID -ne 0 ]]; then
    fail "tcpdump는 루트 권한이 필요합니다. sudo로 다시 실행하거나 --tcpdump 없이 실행하세요."
  else
    info "HTTP/2(NRF:8080)와 PFCP(8805), NGAP(38412) 8패킷 캡처 → $PCAP_PATH"
    timeout 6 tcpdump -i "$BR_IF" -nn -vv -c 8 \
      "tcp port 8080 or udp port 8805 or sctp port 38412" -w "$PCAP_PATH" 2>/dev/null \
      && pass "캡처 완료: $PCAP_PATH" \
      || info "캡처 실패 또는 트래픽 없음"
  fi
fi

echo
echo "========== [완료] =========="
info "이 스크립트 출력은 tee로 파일 저장 권장:"
info "  ./debug-5gc-extended.sh | tee debug-$(date +%F-%H%M).log"

