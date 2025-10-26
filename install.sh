#!/usr/bin/env bash
# ============================================================
#  Sing-Box-Plus Management Script (18 Nodes: Direct 9 + WARP 9)
#  Version: v2.4.6
#  author：Alvin9999
#  Repo: https://github.com/Alvin9999/Sing-Box-Plus
# ============================================================

set -Eeuo pipefail

stty erase ^H # Make backspace work properly in terminal
# ===== [BEGIN] SBP Bootstrap Module v2.2.0+ (Package Manager Priority + Binary Fallback) =====
# Modes & Sentinels
: "${SBP_SOFT:=0}"                               # 1=Lenient mode (try to continue on failures), default 0=Strict
: "${SBP_SKIP_DEPS:=0}"                          # 1=Skip dependency check at startup (install only in menu 1))
: "${SBP_FORCE_DEPS:=0}"                         # 1=Force reinstall dependencies
: "${SBP_BIN_ONLY:=0}"                           # 1=Force binary mode, don't use package manager
: "${SBP_ROOT:=/var/lib/sing-box-plus}"
: "${SBP_BIN_DIR:=${SBP_ROOT}/bin}"
: "${SBP_DEPS_SENTINEL:=/var/lib/sing-box-plus/.deps_ok}"

mkdir -p "$SBP_BIN_DIR" 2>/dev/null || true
export PATH="$SBP_BIN_DIR:$PATH"

# Tool: Downloader + Lightweight Retry
dl() { # Usage: dl <URL> <OUT_PATH>
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --connect-timeout 5 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    timeout 15 wget -qO "$out" --tries=2 "$url"
  else
    echo "[ERROR] Missing curl/wget: Cannot download $url"; return 1
  fi
}
with_retry() { local n=${1:-3}; shift; local i=1; until "$@"; do [ $i -ge "$n" ] && return 1; sleep $((i*2)); i=$((i+1)); done; }

# Tool: Architecture Detection + jq Static Fallback
detect_goarch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    armv7l|armv7) echo armv7 ;;
    i386|i686)    echo 386   ;;
    *)            echo amd64 ;;
  esac
}
ensure_jq_static() {
  command -v jq >/dev/null 2>&1 && return 0
  local arch out="$SBP_BIN_DIR/jq" url alt
  arch="$(detect_goarch)"
  url="https://github.com/jqlang/jq/releases/latest/download/jq-linux-${arch}"
  alt="https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64"
  dl "$url" "$out" || { [ "$arch" = amd64 ] && dl "$alt" "$out" || true; }
  chmod +x "$out" 2>/dev/null || true
  command -v jq >/dev/null 2>&1
}

# Tool: Core Command Self-Check
sbp_core_ok() {
  local need=(curl jq tar unzip openssl)
  local b; for b in "${need[@]}"; do command -v "$b" >/dev/null 2>&1 || return 1; done
  return 0
}

# —— Package Manager Path —— #
sbp_detect_pm() {
  if command -v apt-get >/dev/null 2>&1; then PM=apt
  elif command -v dnf      >/dev/null 2>&1; then PM=dnf
  elif command -v yum      >/dev/null 2>&1; then PM=yum
  elif command -v pacman   >/dev/null 2>&1; then PM=pacman
  elif command -v zypper   >/dev/null 2>&1; then PM=zypper
  else PM=unknown; fi
  [ "$PM" = unknown ] && return 1 || return 0
}

# apt allow release info change (stable→oldstable / Version change)
apt_allow_release_change() {
  cat >/etc/apt/apt.conf.d/99allow-releaseinfo-change <<'CONF'
Acquire::AllowReleaseInfoChange::Suite "true";
Acquire::AllowReleaseInfoChange::Version "true";
CONF
}

# Refresh repositories (with fallbacks for different distros)
sbp_pm_refresh() {
  case "$PM" in
    apt)
      apt_allow_release_change
      sed -i 's#^deb http://#deb https://#' /etc/apt/sources.list 2>/dev/null || true
      # Fix security line for bullseye: bullseye/updates → debian-security bullseye-security
      sed -i -E 's#^(deb\s+https?://security\.debian\.org)(/debian-security)?\s+bullseye/updates(.*)$#\1/debian-security bullseye-security\3#' /etc/apt/sources.list

      local AOPT=""
      curl -6 -fsS --connect-timeout 2 https://deb.debian.org >/dev/null 2>&1 || AOPT='-o Acquire::ForceIPv4=true'

      if ! with_retry 3 apt-get update -y $AOPT; then
        # Temporarily comment out backports 404 and retry
        sed -i 's#^\([[:space:]]*deb .* bullseye-backports.*\)#\# \1#' /etc/apt/sources.list 2>/dev/null || true
        with_retry 2 apt-get update -y $AOPT -o Acquire::Check-Valid-Until=false || [ "$SBP_SOFT" = 1 ]
      fi
      ;;
    dnf)
      dnf clean metadata || true
      with_retry 3 dnf makecache || [ "$SBP_SOFT" = 1 ]
      ;;
    yum)
      yum clean all || true
      with_retry 3 yum makecache fast || true
      yum install -y epel-release || true   # EL7/old environments for jq etc.
      ;;
    pacman)
      pacman-key --init >/dev/null 2>&1 || true
      pacman-key --populate archlinux >/dev/null 2>&1 || true
      with_retry 3 pacman -Syy --noconfirm || [ "$SBP_SOFT" = 1 ]
      ;;
    zypper)
      zypper -n ref || zypper -n ref --force || true
      ;;
  esac
}

# Install packages one by one (single failure doesn't affect overall)
sbp_pm_install() {
  case "$PM" in
    apt)
      local p; apt-get update -y >/dev/null 2>&1 || true
      for p in "$@"; do apt-get install -y --no-install-recommends "$p" || true; done
      ;;
    dnf)
      local p; for p in "$@"; do dnf install -y "$p" || true; done
      ;;
    yum)
      yum install -y epel-release || true
      local p; for p in "$@"; do yum install -y "$p" || true; done
      ;;
    pacman)
      pacman -Sy --noconfirm || [ "$SBP_SOFT" = 1 ]
      local p; for p in "$@"; do pacman -S --noconfirm --needed "$p" || true; done
      ;;
    zypper)
      zypper -n ref || true
      local p; for p in "$@"; do zypper --non-interactive install "$p" || true; done
      ;;
  esac
}

# Install dependencies using package manager
sbp_install_prereqs_pm() {
  sbp_detect_pm || return 1
  sbp_pm_refresh

  case "$PM" in
    apt)    CORE=(curl jq tar unzip openssl); EXTRA=(ca-certificates xz-utils uuid-runtime iproute2 iptables ufw) ;;
    dnf|yum)CORE=(curl jq tar unzip openssl); EXTRA=(ca-certificates xz util-linux iproute iptables iptables-nft firewalld) ;;
    pacman) CORE=(curl jq tar unzip openssl); EXTRA=(ca-certificates xz util-linux iproute2 iptables) ;;
    zypper) CORE=(curl jq tar unzip openssl); EXTRA=(ca-certificates xz util-linux iproute2 iptables firewalld) ;;
    *) return 1 ;;
  esac

  sbp_pm_install "${CORE[@]}" "${EXTRA[@]}"

  # jq fallback: download static jq if package manager installation fails
  if ! command -v jq >/dev/null 2>&1; then
    echo "[INFO] jq installation via package manager failed, trying to download static jq ..."
    ensure_jq_static || { echo "[ERROR] Cannot get jq"; return 1; }
  fi

  # Strict mode: fail if core dependencies still missing
  if ! sbp_core_ok; then
    [ "$SBP_SOFT" = 1 ] || return 1
    echo "[WARN] Core dependencies not ready (continuing in lenient mode)"
  fi
  return 0
}

# —— Binary Mode: Directly get sing-box executable —— #
install_singbox_binary() {
  local arch goarch pkg tmp json url fn
  goarch="$(detect_goarch)"
  tmp="$(mktemp -d)" || return 1

  ensure_jq_static || { echo "[ERROR] Cannot get jq, binary mode failed"; rm -rf "$tmp"; return 1; }

  json="$(with_retry 3 curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest)" || { rm -rf "$tmp"; return 1; }
  url="$(printf '%s' "$json" | jq -r --arg a "$goarch" '
    .assets[] | select(.name|test("linux-" + $a + "\\.(tar\\.(xz|gz)|zip)$")) | .browser_download_url
  ' | head -n1)"

  if [ -z "$url" ] || [ "$url" = "null" ]; then
    echo "[ERROR] No matching sing-box asset found for architecture ($goarch)"; rm -rf "$tmp"; return 1
  fi

  pkg="$tmp/pkg"
  with_retry 3 dl "$url" "$pkg" || { rm -rf "$tmp"; return 1; }

  case "$url" in
    *.tar.xz)  if command -v xz >/dev/null 2>&1; then tar -xJf "$pkg" -C "$tmp"; else echo "[ERROR] Missing xz; please install xz/xz-utils or use .tar.gz/.zip"; rm -rf "$tmp"; return 1; fi ;;
    *.tar.gz)  tar -xzf "$pkg" -C "$tmp" ;;
    *.zip)     unzip -q "$pkg" -d "$tmp" || { echo "[ERROR] Missing unzip"; rm -rf "$tmp"; return 1; } ;;
    *)         echo "[ERROR] Unknown package format: $url"; rm -rf "$tmp"; return 1 ;;
  esac

  fn="$(find "$tmp" -type f -name 'sing-box' | head -n1)"
  [ -n "$fn" ] || { echo "[ERROR] sing-box not found inside package"; rm -rf "$tmp"; return 1; }

  install -m 0755 "$fn" "$SBP_BIN_DIR/sing-box" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  echo "[OK] Installed sing-box to $SBP_BIN_DIR/sing-box"
}

# Certificate fallback (generate if openssl available; skip if not, let service decide if to force)
ensure_tls_cert() {
  local dir="$SBP_ROOT"
  mkdir -p "$dir"
  if command -v openssl >/dev/null 2>&1; then
    [[ -f "$dir/private.key" ]] || openssl ecparam -genkey -name prime256v1 -out "$dir/private.key" >/dev/null 2>&1
    [[ -f "$dir/cert.pem"    ]] || openssl req -new -x509 -days 36500 -key "$dir/private.key" -out "$dir/cert.pem" -subj "/CN=www.bing.com" >/dev/null 2>&1
  fi
}

# Mark Sentinel
sbp_mark_deps_ok() {
  if sbp_core_ok; then
    mkdir -p "$(dirname "$SBP_DEPS_SENTINEL")" && : > "$SBP_DEPS_SENTINEL" || true
  fi
}

# Entry: Install dependencies / Binary fallback
sbp_bootstrap() {
  [ "$EUID" -eq 0 ] || { echo "Please run as root (or sudo)"; exit 1; }

  if [ "$SBP_SKIP_DEPS" = 1 ]; then
    echo "[INFO] Skipped startup dependency check (SBP_SKIP_DEPS=1)"
    return 0
  fi

  # Skip if already ready
  if [ "$SBP_FORCE_DEPS" != 1 ] && sbp_core_ok && [ -f "$SBP_DEPS_SENTINEL" ] && [ "$SBP_BIN_ONLY" != 1 ]; then
    echo "Dependencies already installed"
    return 0
  fi

  # Force binary mode
  if [ "$SBP_BIN_ONLY" = 1 ]; then
    echo "[INFO] Binary mode (SBP_BIN_ONLY=1)"
    install_singbox_binary || { echo "[ERROR] Binary mode sing-box installation failed"; exit 1; }
    ensure_tls_cert
    return 0
  fi

  # Package manager priority
  if sbp_install_prereqs_pm; then
    sbp_mark_deps_ok
    return 0
  fi

  # Fallback to binary mode
  echo "[WARN] Package manager dependency installation failed, switching to binary mode"
  install_singbox_binary || { echo "[ERROR] Binary mode sing-box installation failed"; exit 1; }
  ensure_tls_cert
}
# ===== [END] SBP Bootstrap Module v2.2.0+ =====


# ===== Set defaults early to avoid script exit due to undefined variable references with set -u =====
SYSTEMD_SERVICE=${SYSTEMD_SERVICE:-sing-box.service}
BIN_PATH=${BIN_PATH:-/usr/local/bin/sing-box}
SB_DIR=${SB_DIR:-/opt/sing-box}
CONF_JSON=${CONF_JSON:-$SB_DIR/config.json}
DATA_DIR=${DATA_DIR:-$SB_DIR/data}
CERT_DIR=${CERT_DIR:-$SB_DIR/cert}
WGCF_DIR=${WGCF_DIR:-$SB_DIR/wgcf}

# Feature Toggles (Keep stable defaults)
ENABLE_WARP=${ENABLE_WARP:-true}
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
ENABLE_HY2_OBFS=${ENABLE_HY2_OBFS:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SS=${ENABLE_SS:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}

# Constants
SCRIPT_NAME="Sing-Box-Plus Management Script"
SCRIPT_VERSION="v2.4.6"
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

# Compatibility for sing-box 1.12.x old wireguard outbound
export ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND:-true}

# ===== Colors =====
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"; C_MAGENTA="\033[35m"
hr(){ printf "${C_DIM}=============================================================${C_RESET}\n"; }

# ===== Basic Tools =====
info(){ echo -e "[${C_CYAN}INFO${C_RESET}] $*"; }
warn(){ echo -e "[${C_YELLOW}WARN${C_RESET}] $*"; }
die(){  echo -e "[${C_RED}ERROR${C_RESET}] $*" >&2; exit 1; }

# --- Architecture Mapping: uname -m -> release asset name ---
arch_map() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    armv6l)       echo "armv7" ;;   # No upstream armv6, fallback to armv7
    i386|i686)    echo "386"  ;;
    *)            echo "amd64" ;;
  esac
}

# --- Dependency Installation: Compatible with apt / yum / dnf / apk / pacman / zypper ---
ensure_deps() {
  local pkgs=("$@") miss=()
  for p in "${pkgs[@]}"; do command -v "$p" >/dev/null 2>&1 || miss+=("$p"); done
  ((${#miss[@]}==0)) && return 0

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${miss[@]}" || apt-get install -y --no-install-recommends "${miss[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${miss[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${miss[@]}"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "${miss[@]}"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm "${miss[@]}"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "${miss[@]}"
  else
    err "Cannot automatically install dependencies: ${miss[*]}, please install manually and retry"
    return 1
  fi
}

b64enc(){ base64 -w 0 2>/dev/null || base64; }
urlenc(){ # Pure bash urlencode (no python dependency)
  local s="$1" out="" c
  for ((i=0; i<${#s}; i++)); do
    c=${s:i:1}
    case "$c" in
      [a-zA-Z0-9._~-]) out+="$c" ;;
      ' ') out+="%20" ;;
      *) printf -v out "%s%%%02X" "$out" "'$c" ;;
    esac
  done
  printf "%s" "$out"
}

safe_source_env(){ # Safe source, ignore non-existent files
  local f="$1"; [[ -f "$f" ]] || return 1
  set +u; # Avoid undefined variable errors
  # shellcheck disable=SC1090
  source "$f"
  set -u
}

get_ip(){ # Get public IP from multiple sources
  local ip
  ip=$(curl -fsSL ipv4.icanhazip.com || true)
  [[ -z "$ip" ]] && ip=$(curl -fsSL ifconfig.me || true)
  [[ -z "$ip" ]] && ip=$(curl -fsSL ip.sb || true)
  echo "${ip:-127.0.0.1}"
}

is_uuid(){ [[ "$1" =~ ^[0-9a-fA-F-]{36}$ ]]; }

ensure_dirs(){ mkdir -p "$SB_DIR" "$DATA_DIR" "$CERT_DIR" "$WGCF_DIR"; }

# ===== Ports (18 mutually exclusive) =====
PORTS=()
gen_port() {
  while :; do
    p=$(( ( RANDOM % 55536 ) + 10000 ))
    [[ $p -le 65535 ]] || continue
    [[ " ${PORTS[*]-} " != *" $p "* ]] && { PORTS+=("$p"); echo "$p"; return; }
  done
}
rand_ports_reset(){ PORTS=(); }

PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""
PORT_VLESSR_W=""; PORT_VLESS_GRPCR_W=""; PORT_TROJANR_W=""; PORT_HY2_W=""; PORT_VMESS_WS_W=""
PORT_HY2_OBFS_W=""; PORT_SS2022_W=""; PORT_SS_W=""; PORT_TUIC_W=""

save_ports(){ cat > "$SB_DIR/ports.env" <<EOF
PORT_VLESSR=$PORT_VLESSR
PORT_VLESS_GRPCR=$PORT_VLESS_GRPCR
PORT_TROJANR=$PORT_TROJANR
PORT_HY2=$PORT_HY2
PORT_VMESS_WS=$PORT_VMESS_WS
PORT_HY2_OBFS=$PORT_HY2_OBFS
PORT_SS2022=$PORT_SS2022
PORT_SS=$PORT_SS
PORT_TUIC=$PORT_TUIC
PORT_VLESSR_W=$PORT_VLESSR_W
PORT_VLESS_GRPCR_W=$PORT_VLESS_GRPCR_W
PORT_TROJANR_W=$PORT_TROJANR_W
PORT_HY2_W=$PORT_HY2_W
PORT_VMESS_WS_W=$PORT_VMESS_WS_W
PORT_HY2_OBFS_W=$PORT_HY2_OBFS_W
PORT_SS2022_W=$PORT_SS2022_W
PORT_SS_W=$PORT_SS_W
PORT_TUIC_W=$PORT_TUIC_W
EOF
}
load_ports(){ safe_source_env "$SB_DIR/ports.env" || return 1; }

save_all_ports(){
  rand_ports_reset
  for v in PORT_VLESSR PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_VMESS_WS PORT_HY2_OBFS PORT_SS2022 PORT_SS PORT_TUIC \
           PORT_VLESSR_W PORT_VLESS_GRPCR_W PORT_TROJANR_W PORT_HY2_W PORT_VMESS_WS_W PORT_HY2_OBFS_W PORT_SS2022_W PORT_SS_W PORT_TUIC_W; do
    [[ -n "${!v:-}" ]] && PORTS+=("${!v}")
  done
  [[ -z "${PORT_VLESSR:-}" ]] && PORT_VLESSR=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR:-}" ]] && PORT_VLESS_GRPCR=$(gen_port)
  [[ -z "${PORT_TROJANR:-}" ]] && PORT_TROJANR=$(gen_port)
  [[ -z "${PORT_HY2:-}" ]] && PORT_HY2=$(gen_port)
  [[ -z "${PORT_VMESS_WS:-}" ]] && PORT_VMESS_WS=$(gen_port)
  [[ -z "${PORT_HY2_OBFS:-}" ]] && PORT_HY2_OBFS=$(gen_port)
  [[ -z "${PORT_SS2022:-}" ]] && PORT_SS2022=$(gen_port)
  [[ -z "${PORT_SS:-}" ]] && PORT_SS=$(gen_port)
  [[ -z "${PORT_TUIC:-}" ]] && PORT_TUIC=$(gen_port)
  [[ -z "${PORT_VLESSR_W:-}" ]] && PORT_VLESSR_W=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR_W:-}" ]] && PORT_VLESS_GRPCR_W=$(gen_port)
  [[ -z "${PORT_TROJANR_W:-}" ]] && PORT_TROJANR_W=$(gen_port)
  [[ -z "${PORT_HY2_W:-}" ]] && PORT_HY2_W=$(gen_port)
  [[ -z "${PORT_VMESS_WS_W:-}" ]] && PORT_VMESS_WS_W=$(gen_port)
  [[ -z "${PORT_HY2_OBFS_W:-}" ]] && PORT_HY2_OBFS_W=$(gen_port) || true
  [[ -z "${PORT_SS2022_W:-}" ]] && PORT_SS2022_W=$(gen_port)
  [[ -z "${PORT_SS_W:-}" ]] && PORT_SS_W=$(gen_port)
  [[ -z "${PORT_TUIC_W:-}" ]] && PORT_TUIC_W=$(gen_port)
  save_ports
}

# ===== env / creds / warp =====
save_env(){ cat > "$SB_DIR/env.conf" <<EOF
BIN_PATH=$BIN_PATH
ENABLE_VLESS_REALITY=$ENABLE_VLESS_REALITY
ENABLE_VLESS_GRPCR=$ENABLE_VLESS_GRPCR
ENABLE_TROJAN_REALITY=$ENABLE_TROJAN_REALITY
ENABLE_HYSTERIA2=$ENABLE_HYSTERIA2
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
ENABLE_HY2_OBFS=$ENABLE_HY2_OBFS
ENABLE_SS2022=$ENABLE_SS2022
ENABLE_SS=$ENABLE_SS
ENABLE_TUIC=$ENABLE_TUIC
ENABLE_WARP=$ENABLE_WARP
REALITY_SERVER=$REALITY_SERVER
REALITY_SERVER_PORT=$REALITY_SERVER_PORT
GRPC_SERVICE=$GRPC_SERVICE
VMESS_WS_PATH=$VMESS_WS_PATH
EOF
}
load_env(){ safe_source_env "$SB_DIR/env.conf" || true; }

save_creds(){ cat > "$SB_DIR/creds.env" <<EOF
UUID=$UUID
HY2_PWD=$HY2_PWD
REALITY_PRIV=$REALITY_PRIV
REALITY_PUB=$REALITY_PUB
REALITY_SID=$REALITY_SID
HY2_PWD2=$HY2_PWD2
HY2_OBFS_PWD=$HY2_OBFS_PWD
SS2022_KEY=$SS2022_KEY
SS_PWD=$SS_PWD
TUIC_UUID=$TUIC_UUID
TUIC_PWD=$TUIC_PWD
EOF
}
load_creds(){ safe_source_env "$SB_DIR/creds.env" || return 1; }

save_warp(){ cat > "$SB_DIR/warp.env" <<EOF
WARP_PRIVATE_KEY=$WARP_PRIVATE_KEY
WARP_PEER_PUBLIC_KEY=$WARP_PEER_PUBLIC_KEY
WARP_ENDPOINT_HOST=$WARP_ENDPOINT_HOST
WARP_ENDPOINT_PORT=$WARP_ENDPOINT_PORT
WARP_ADDRESS_V4=$WARP_ADDRESS_V4
WARP_ADDRESS_V6=$WARP_ADDRESS_V6
WARP_RESERVED_1=$WARP_RESERVED_1
WARP_RESERVED_2=$WARP_RESERVED_2
WARP_RESERVED_3=$WARP_RESERVED_3
EOF
}
load_warp(){ safe_source_env "$SB_DIR/warp.env" || return 1; }

# Generate 8-byte hex (16 hex characters)
rand_hex8(){
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 8 | tr -d "\n"
  else
    # Fallback: use hexdump if no openssl
    hexdump -v -n 8 -e '1/1 "%02x"' /dev/urandom
  fi
}
rand_b64_32(){ openssl rand -base64 32 | tr -d "\n"; }

gen_uuid(){
  local u=""
  if [[ -x "$BIN_PATH" ]]; then u=$("$BIN_PATH" generate uuid 2>/dev/null | head -n1); fi
  if [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1; then u=$(uuidgen | head -n1); fi
  if [[ -z "$u" ]]; then u=$(cat /proc/sys/kernel/random/uuid | head -n1); fi
  printf '%s' "$u" | tr -d '\r\n'
}
gen_reality(){ "$BIN_PATH" generate reality-keypair; }

mk_cert(){
  local crt="$CERT_DIR/fullchain.pem" key="$CERT_DIR/key.pem"
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -keyout "$key" -out "$crt" -subj "/CN=$REALITY_SERVER" \
      -addext "subjectAltName=DNS:$REALITY_SERVER" >/dev/null 2>&1
  fi
}

ensure_creds(){
  [[ -z "${UUID:-}" ]] && UUID=$(gen_uuid)
  is_uuid "$UUID" || UUID=$(gen_uuid)
  [[ -z "${HY2_PWD:-}" ]] && HY2_PWD=$(rand_b64_32)
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    readarray -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')
    REALITY_SID=$(rand_hex8)
  fi
  [[ -z "${HY2_PWD2:-}" ]] && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]] && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d "\n")
  [[ -z "${SS2022_KEY:-}" ]] && SS2022_KEY=$(rand_b64_32)
  [[ -z "${SS_PWD:-}" ]] && SS_PWD=$(openssl rand -base64 24 | tr -d "=\n" | tr "+/" "-_")
  TUIC_UUID="$UUID"; TUIC_PWD="$UUID"
  save_creds
}

# ===== WARP (wgcf) =====
WGCF_BIN=/usr/local/bin/wgcf
install_wgcf(){
  [[ -x "$WGCF_BIN" ]] && return 0
  local GOA url tmp
  case "$(arch_map)" in
    amd64) GOA=amd64;; arm64) GOA=arm64;; armv7) GOA=armv7;; 386) GOA=386;; *) GOA=amd64;;
  esac
  url=$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | jq -r ".assets[] | select(.name|test(\"linux_${GOA}$\")) | .browser_download_url" | head -n1)
  [[ -n "$url" ]] || { warn "Failed to get wgcf download URL"; return 1; }
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/wgcf"
  install -m0755 "$tmp/wgcf" "$WGCF_BIN"
  rm -rf "$tmp"
}

# —— Base64 cleanup + padding: remove quotes/whitespace, length %4==2 add "==", %4==3 add "=" ——
pad_b64(){
  local s="${1:-}"
  # Remove quotes/spaces/carriage returns
  s="$(printf '%s' "$s" | tr -d '\r\n\" ')"
  # Remove existing trailing =, re-add as needed
  s="${s%%=*}"
  local rem=$(( ${#s} % 4 ))
  if   (( rem == 2 )); then s="${s}=="
  elif (( rem == 3 )); then s="${s}="
  fi
  printf '%s' "$s"
}


# ===== WARP (wgcf) Configuration Generation/Fix =====
ensure_warp_profile(){
  [[ "${ENABLE_WARP:-true}" == "true" ]] || return 0

  # First try to read old env and do one normalization/padding
  if load_warp 2>/dev/null; then
    WARP_PRIVATE_KEY="$(pad_b64 "${WARP_PRIVATE_KEY:-}")"
    WARP_PEER_PUBLIC_KEY="$(pad_b64 "${WARP_PEER_PUBLIC_KEY:-}")"
    # Allow reserved not written before, set default 0
    : "${WARP_RESERVED_1:=0}" "${WARP_RESERVED_2:=0}" "${WARP_RESERVED_3:=0}"
    save_warp
    # If key fields are present, use the old ones (already padded), no need to rebuild
    if [[ -n "$WARP_PRIVATE_KEY" && -n "$WARP_PEER_PUBLIC_KEY" && -n "${WARP_ENDPOINT_HOST:-}" && -n "${WARP_ENDPOINT_PORT:-}" ]]; then
      return 0
    fi
  fi

  # Reaching here means old env is incomplete; start rebuilding with wgcf
  install_wgcf || { warn "wgcf installation failed, disabling WARP node"; ENABLE_WARP=false; save_env; return 0; }

  local wd="$SB_DIR/wgcf"; mkdir -p "$wd"
  if [[ ! -f "$wd/wgcf-account.toml" ]]; then
    "$WGCF_BIN" register --accept-tos --config "$wd/wgcf-account.toml" >/dev/null
  fi
  "$WGCF_BIN" generate --config "$wd/wgcf-account.toml" --profile "$wd/wgcf-profile.conf" >/dev/null

  local prof="$wd/wgcf-profile.conf"
  # Extract and normalize
  WARP_PRIVATE_KEY="$(pad_b64 "$(awk -F'= *' '/^PrivateKey/{gsub(/\r/,"");print $2; exit}' "$prof")")"
  WARP_PEER_PUBLIC_KEY="$(pad_b64 "$(awk -F'= *' '/^PublicKey/{gsub(/\r/,"");print $2; exit}' "$prof")")"
  WARP_ENDPOINT_HOST="$(awk -F'= *' '/^Endpoint/{gsub(/\r/,"");print $2}' "$prof" | cut -d: -f1)"
  WARP_ENDPOINT_PORT="$(awk -F'= *' '/^Endpoint/{gsub(/\r/,"");print $2}' "$prof" | cut -d: -f2)"
  WARP_ADDRESS_V4="$(awk -F'= *' '/^Address/{gsub(/\r/,"");print $2}' "$prof" | grep : | head -n1 | cut -d, -f1)"
  WARP_ADDRESS_V6="$(awk -F'= *' '/^Address/{gsub(/\r/,"");print $2}' "$prof" | grep : | tail -n1 | cut -d, -f1)"
  # Reserved: extract from PrivateKey base64 decoded [5:8]
  local priv_decoded
  priv_decoded="$(printf '%s' "$WARP_PRIVATE_KEY" | base64 -d 2>/dev/null | od -An -tu1 -N8 | tr -s ' \n' ',')"
  priv_decoded="${priv_decoded%,}"
  WARP_RESERVED_1="$(echo "$priv_decoded" | cut -d, -f1)"
  WARP_RESERVED_2="$(echo "$priv_decoded" | cut -d, -f2)"
  WARP_RESERVED_3="$(echo "$priv_decoded" | cut -d, -f3)"
  save_warp
}

# ===== Configuration Generation =====
gen_config(){
  ensure_dirs; ensure_creds; ensure_warp_profile; mk_cert
  load_creds; load_warp; load_ports

  local ip; ip=$(get_ip)
  local warp_enabled="${ENABLE_WARP:-true}"
  local warp_outbound=""
  if [[ "$warp_enabled" == "true" ]]; then
    warp_outbound=$(cat <<EOF
        {
          "type": "wireguard",
          "tag": "wireguard-out",
          "server": "$WARP_ENDPOINT_HOST",
          "server_port": $WARP_ENDPOINT_PORT,
          "local_address": [
            "$WARP_ADDRESS_V4",
            "$WARP_ADDRESS_V6"
          ],
          "private_key": "$WARP_PRIVATE_KEY",
          "peer_public_key": "$WARP_PEER_PUBLIC_KEY",
          "reserved": [$WARP_RESERVED_1, $WARP_RESERVED_2, $WARP_RESERVED_3],
          "mtu": 1280
        }
EOF
)
  fi

  cat > "$CONF_JSON" <<EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "tls://8.8.8.8",
        "detour": "direct"
      },
      {
        "tag": "remote",
        "address": "tls://8.8.8.8",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "local"
      }
    ],
    "strategy": "ipv4_only"
  },
  "inbounds": [
EOF

  # Direct nodes
  if [[ "${ENABLE_VLESS_REALITY:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": $PORT_VLESSR,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$UUID",
          "flow": ""
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SERVER",
            "server_port": $REALITY_SERVER_PORT
          },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      }
    },
EOF
  fi

  if [[ "${ENABLE_VLESS_GRPCR:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "vless",
      "tag": "vless-grpc-in",
      "listen": "::",
      "listen_port": $PORT_VLESS_GRPCR,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$UUID",
          "flow": ""
        }
      ],
      "transport": {
        "type": "grpc",
        "service_name": "$GRPC_SERVICE"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
  fi

  if [[ "${ENABLE_TROJAN_REALITY:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "trojan",
      "tag": "trojan-reality-in",
      "listen": "::",
      "listen_port": $PORT_TROJANR,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "password": "$UUID"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SERVER",
            "server_port": $REALITY_SERVER_PORT
          },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      }
    },
EOF
  fi

  if [[ "${ENABLE_HYSTERIA2:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [
        {
          "password": "$HY2_PWD"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
  fi

  if [[ "${ENABLE_VMESS_WS:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "vmess",
      "tag": "vmess-ws-in",
      "listen": "::",
      "listen_port": $PORT_VMESS_WS,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$UUID",
          "alterId": 0
        }
      ],
      "transport": {
        "type": "ws",
        "path": "$VMESS_WS_PATH"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
  fi

  if [[ "${ENABLE_HY2_OBFS:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "hysteria2",
      "tag": "hysteria2-obfs-in",
      "listen": "::",
      "listen_port": $PORT_HY2_OBFS,
      "users": [
        {
          "password": "$HY2_OBFS_PWD"
        }
      ],
      "obfs": {
        "type": "salamander",
        "password": "$HY2_OBFS_PWD"
      }
    },
EOF
  fi

  if [[ "${ENABLE_SS2022:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "shadowsocks",
      "tag": "ss2022-in",
      "listen": "::",
      "listen_port": $PORT_SS2022,
      "method": "2022-blake3-aes-128-gcm",
      "password": "$SS2022_KEY"
    },
EOF
  fi

  if [[ "${ENABLE_SS:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": $PORT_SS,
      "method": "aes-128-gcm",
      "password": "$SS_PWD"
    },
EOF
  fi

  if [[ "${ENABLE_TUIC:-true}" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": $PORT_TUIC,
      "users": [
        {
          "uuid": "$TUIC_UUID",
          "password": "$TUIC_PWD"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
  fi

  # WARP nodes
  if [[ "$warp_enabled" == "true" ]]; then
    if [[ "${ENABLE_VLESS_REALITY:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "vless",
      "tag": "vless-reality-in-w",
      "listen": "::",
      "listen_port": $PORT_VLESSR_W,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$UUID",
          "flow": ""
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SERVER",
            "server_port": $REALITY_SERVER_PORT
          },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      }
    },
EOF
    fi

    if [[ "${ENABLE_VLESS_GRPCR:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "vless",
      "tag": "vless-grpc-in-w",
      "listen": "::",
      "listen_port": $PORT_VLESS_GRPCR_W,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$UUID",
          "flow": ""
        }
      ],
      "transport": {
        "type": "grpc",
        "service_name": "$GRPC_SERVICE"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
    fi

    if [[ "${ENABLE_TROJAN_REALITY:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "trojan",
      "tag": "trojan-reality-in-w",
      "listen": "::",
      "listen_port": $PORT_TROJANR_W,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "password": "$UUID"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SERVER",
            "server_port": $REALITY_SERVER_PORT
          },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      }
    },
EOF
    fi

    if [[ "${ENABLE_HYSTERIA2:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "hysteria2",
      "tag": "hysteria2-in-w",
      "listen": "::",
      "listen_port": $PORT_HY2_W,
      "users": [
        {
          "password": "$HY2_PWD2"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
    fi

    if [[ "${ENABLE_VMESS_WS:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "vmess",
      "tag": "vmess-ws-in-w",
      "listen": "::",
      "listen_port": $PORT_VMESS_WS_W,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$UUID",
          "alterId": 0
        }
      ],
      "transport": {
        "type": "ws",
        "path": "$VMESS_WS_PATH"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
    fi

    if [[ "${ENABLE_HY2_OBFS:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "hysteria2",
      "tag": "hysteria2-obfs-in-w",
      "listen": "::",
      "listen_port": $PORT_HY2_OBFS_W,
      "users": [
        {
          "password": "$HY2_OBFS_PWD"
        }
      ],
      "obfs": {
        "type": "salamander",
        "password": "$HY2_OBFS_PWD"
      }
    },
EOF
    fi

    if [[ "${ENABLE_SS2022:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "shadowsocks",
      "tag": "ss2022-in-w",
      "listen": "::",
      "listen_port": $PORT_SS2022_W,
      "method": "2022-blake3-aes-128-gcm",
      "password": "$SS2022_KEY"
    },
EOF
    fi

    if [[ "${ENABLE_SS:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "shadowsocks",
      "tag": "ss-in-w",
      "listen": "::",
      "listen_port": $PORT_SS_W,
      "method": "aes-128-gcm",
      "password": "$SS_PWD"
    },
EOF
    fi

    if [[ "${ENABLE_TUIC:-true}" == "true" ]]; then
      cat >> "$CONF_JSON" <<EOF
    {
      "type": "tuic",
      "tag": "tuic-in-w",
      "listen": "::",
      "listen_port": $PORT_TUIC_W,
      "users": [
        {
          "uuid": "$TUIC_UUID",
          "password": "$TUIC_PWD"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    },
EOF
    fi
  fi

  # Remove trailing comma from last inbound
  truncate -s-2 "$CONF_JSON"

  cat >> "$CONF_JSON" <<EOF
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
EOF

  if [[ "$warp_enabled" == "true" ]]; then
    cat >> "$CONF_JSON" <<EOF
    ,
    $warp_outbound
EOF
  fi

  cat >> "$CONF_JSON" <<EOF
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "network": "udp",
        "port": [
          443
        ],
        "outbound": "block"
      }
    ]
  }
}
EOF

  chmod 600 "$CONF_JSON"
}

# ===== Client Configuration Generation =====
gen_clients(){
  ensure_dirs; load_creds; load_warp; load_ports
  local ip; ip=$(get_ip)
  local warp_enabled="${ENABLE_WARP:-true}"
  local warp_direct="direct" warp_proxy="wireguard-out"
  [[ "$warp_enabled" != "true" ]] && { warp_direct="direct"; warp_proxy="direct"; }

  mkdir -p "$SB_DIR/clients"
  local cdir="$SB_DIR/clients"

  # Direct nodes
  if [[ "${ENABLE_VLESS_REALITY:-true}" == "true" ]]; then
    cat > "$cdir/vless-reality.json" <<EOF
{
  "type": "vless",
  "tag": "vless-reality-out",
  "server": "$ip",
  "server_port": $PORT_VLESSR,
  "uuid": "$UUID",
  "flow": "",
  "tls": {
    "enabled": true,
    "server_name": "$REALITY_SERVER",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "$REALITY_PUB",
      "short_id": "$REALITY_SID"
    }
  }
}
EOF
    echo -e "vless://$UUID@$ip:$PORT_VLESSR?encryption=none&flow=&security=reality&sni=$(urlenc "$REALITY_SERVER")&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#$ip-vless-reality" > "$cdir/vless-reality-url.txt"
  fi

  if [[ "${ENABLE_VLESS_GRPCR:-true}" == "true" ]]; then
    cat > "$cdir/vless-grpc.json" <<EOF
{
  "type": "vless",
  "tag": "vless-grpc-out",
  "server": "$ip",
  "server_port": $PORT_VLESS_GRPCR,
  "uuid": "$UUID",
  "flow": "",
  "transport": {
    "type": "grpc",
    "service_name": "$GRPC_SERVICE"
  },
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
EOF
    echo -e "vless://$UUID@$ip:$PORT_VLESS_GRPCR?encryption=none&flow=&security=tls&sni=$ip&fp=chrome&type=grpc&serviceName=$(urlenc "$GRPC_SERVICE")&mode=gun#$ip-vless-grpc" > "$cdir/vless-grpc-url.txt"
  fi

  if [[ "${ENABLE_TROJAN_REALITY:-true}" == "true" ]]; then
    cat > "$cdir/trojan-reality.json" <<EOF
{
  "type": "trojan",
  "tag": "trojan-reality-out",
  "server": "$ip",
  "server_port": $PORT_TROJANR,
  "password": "$UUID",
  "tls": {
    "enabled": true,
    "server_name": "$REALITY_SERVER",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "$REALITY_PUB",
      "short_id": "$REALITY_SID"
    }
  }
}
EOF
    echo -e "trojan://$UUID@$ip:$PORT_TROJANR?security=reality&sni=$(urlenc "$REALITY_SERVER")&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#$ip-trojan-reality" > "$cdir/trojan-reality-url.txt"
  fi

  if [[ "${ENABLE_HYSTERIA2:-true}" == "true" ]]; then
    cat > "$cdir/hysteria2.json" <<EOF
{
  "type": "hysteria2",
  "tag": "hysteria2-out",
  "server": "$ip",
  "server_port": $PORT_HY2,
  "password": "$HY2_PWD",
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "insecure": false
  }
}
EOF
    echo -e "hysteria2://$HY2_PWD@$ip:$PORT_HY2?insecure=0&sni=$ip#$ip-hysteria2" > "$cdir/hysteria2-url.txt"
  fi

  if [[ "${ENABLE_VMESS_WS:-true}" == "true" ]]; then
    cat > "$cdir/vmess-ws.json" <<EOF
{
  "type": "vmess",
  "tag": "vmess-ws-out",
  "server": "$ip",
  "server_port": $PORT_VMESS_WS,
  "uuid": "$UUID",
  "security": "auto",
  "alterId": 0,
  "transport": {
    "type": "ws",
    "path": "$VMESS_WS_PATH",
    "headers": {}
  },
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "insecure": false
  }
}
EOF
    local vmess_json="{\"v\": \"2\", \"ps\": \"$ip-vmess-ws\", \"add\": \"$ip\", \"port\": \"$PORT_VMESS_WS\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"$VMESS_WS_PATH\", \"tls\": \"tls\", \"sni\": \"$ip\"}"
    echo -e "vmess://$(printf '%s' "$vmess_json" | base64 -w 0)" > "$cdir/vmess-ws-url.txt"
  fi

  if [[ "${ENABLE_HY2_OBFS:-true}" == "true" ]]; then
    cat > "$cdir/hysteria2-obfs.json" <<EOF
{
  "type": "hysteria2",
  "tag": "hysteria2-obfs-out",
  "server": "$ip",
  "server_port": $PORT_HY2_OBFS,
  "password": "$HY2_OBFS_PWD",
  "obfs": {
    "type": "salamander",
    "password": "$HY2_OBFS_PWD"
  }
}
EOF
    echo -e "hysteria2://$HY2_OBFS_PWD@$ip:$PORT_HY2_OBFS?obfs=salamander&obfs-password=$(urlenc "$HY2_OBFS_PWD")&insecure=1#$ip-hysteria2-obfs" > "$cdir/hysteria2-obfs-url.txt"
  fi

  if [[ "${ENABLE_SS2022:-true}" == "true" ]]; then
    cat > "$cdir/ss2022.json" <<EOF
{
  "type": "shadowsocks",
  "tag": "ss2022-out",
  "server": "$ip",
  "server_port": $PORT_SS2022,
  "method": "2022-blake3-aes-128-gcm",
  "password": "$SS2022_KEY"
}
EOF
    local ss2022_b64=$(printf '%s' "2022-blake3-aes-128-gcm:${SS2022_KEY}" | b64enc)
    echo -e "ss://$ss2022_b64@$ip:$PORT_SS2022#$ip-ss2022" > "$cdir/ss2022-url.txt"
  fi

  if [[ "${ENABLE_SS:-true}" == "true" ]]; then
    cat > "$cdir/ss.json" <<EOF
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "$ip",
  "server_port": $PORT_SS,
  "method": "aes-128-gcm",
  "password": "$SS_PWD"
}
EOF
    local ss_b64=$(printf '%s' "aes-128-gcm:${SS_PWD}" | b64enc)
    echo -e "ss://$ss_b64@$ip:$PORT_SS#$ip-ss" > "$cdir/ss-url.txt"
  fi

  if [[ "${ENABLE_TUIC:-true}" == "true" ]]; then
    cat > "$cdir/tuic.json" <<EOF
{
  "type": "tuic",
  "tag": "tuic-out",
  "server": "$ip",
  "server_port": $PORT_TUIC,
  "uuid": "$TUIC_UUID",
  "password": "$TUIC_PWD",
  "congestion_control": "bbr",
  "udp_relay_mode": "native",
  "zero_rtt_handshake": false,
  "heartbeat": "10s",
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "insecure": false
  }
}
EOF
    echo -e "tuic://$TUIC_UUID:$TUIC_PWD@$ip:$PORT_TUIC?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$ip&allow_insecure=0#$ip-tuic" > "$cdir/tuic-url.txt"
  fi

  # WARP nodes
  if [[ "$warp_enabled" == "true" ]]; then
    if [[ "${ENABLE_VLESS_REALITY:-true}" == "true" ]]; then
      cat > "$cdir/vless-reality-warp.json" <<EOF
{
  "type": "vless",
  "tag": "vless-reality-out-w",
  "server": "$ip",
  "server_port": $PORT_VLESSR_W,
  "uuid": "$UUID",
  "flow": "",
  "tls": {
    "enabled": true,
    "server_name": "$REALITY_SERVER",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "$REALITY_PUB",
      "short_id": "$REALITY_SID"
    }
  },
  "detour": "$warp_proxy"
}
EOF
      echo -e "vless://$UUID@$ip:$PORT_VLESSR_W?encryption=none&flow=&security=reality&sni=$(urlenc "$REALITY_SERVER")&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#$ip-vless-reality-warp" > "$cdir/vless-reality-warp-url.txt"
    fi

    if [[ "${ENABLE_VLESS_GRPCR:-true}" == "true" ]]; then
      cat > "$cdir/vless-grpc-warp.json" <<EOF
{
  "type": "vless",
  "tag": "vless-grpc-out-w",
  "server": "$ip",
  "server_port": $PORT_VLESS_GRPCR_W,
  "uuid": "$UUID",
  "flow": "",
  "transport": {
    "type": "grpc",
    "service_name": "$GRPC_SERVICE"
  },
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  },
  "detour": "$warp_proxy"
}
EOF
      echo -e "vless://$UUID@$ip:$PORT_VLESS_GRPCR_W?encryption=none&flow=&security=tls&sni=$ip&fp=chrome&type=grpc&serviceName=$(urlenc "$GRPC_SERVICE")&mode=gun#$ip-vless-grpc-warp" > "$cdir/vless-grpc-warp-url.txt"
    fi

    if [[ "${ENABLE_TROJAN_REALITY:-true}" == "true" ]]; then
      cat > "$cdir/trojan-reality-warp.json" <<EOF
{
  "type": "trojan",
  "tag": "trojan-reality-out-w",
  "server": "$ip",
  "server_port": $PORT_TROJANR_W,
  "password": "$UUID",
  "tls": {
    "enabled": true,
    "server_name": "$REALITY_SERVER",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "$REALITY_PUB",
      "short_id": "$REALITY_SID"
    }
  },
  "detour": "$warp_proxy"
}
EOF
      echo -e "trojan://$UUID@$ip:$PORT_TROJANR_W?security=reality&sni=$(urlenc "$REALITY_SERVER")&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#$ip-trojan-reality-warp" > "$cdir/trojan-reality-warp-url.txt"
    fi

    if [[ "${ENABLE_HYSTERIA2:-true}" == "true" ]]; then
      cat > "$cdir/hysteria2-warp.json" <<EOF
{
  "type": "hysteria2",
  "tag": "hysteria2-out-w",
  "server": "$ip",
  "server_port": $PORT_HY2_W,
  "password": "$HY2_PWD2",
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "insecure": false
  },
  "detour": "$warp_proxy"
}
EOF
      echo -e "hysteria2://$HY2_PWD2@$ip:$PORT_HY2_W?insecure=0&sni=$ip#$ip-hysteria2-warp" > "$cdir/hysteria2-warp-url.txt"
    fi

    if [[ "${ENABLE_VMESS_WS:-true}" == "true" ]]; then
      cat > "$cdir/vmess-ws-warp.json" <<EOF
{
  "type": "vmess",
  "tag": "vmess-ws-out-w",
  "server": "$ip",
  "server_port": $PORT_VMESS_WS_W,
  "uuid": "$UUID",
  "security": "auto",
  "alterId": 0,
  "transport": {
    "type": "ws",
    "path": "$VMESS_WS_PATH",
    "headers": {}
  },
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "insecure": false
  },
  "detour": "$warp_proxy"
}
EOF
      local vmess_json_w="{\"v\": \"2\", \"ps\": \"$ip-vmess-ws-warp\", \"add\": \"$ip\", \"port\": \"$PORT_VMESS_WS_W\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"$VMESS_WS_PATH\", \"tls\": \"tls\", \"sni\": \"$ip\"}"
      echo -e "vmess://$(printf '%s' "$vmess_json_w" | base64 -w 0)" > "$cdir/vmess-ws-warp-url.txt"
    fi

    if [[ "${ENABLE_HY2_OBFS:-true}" == "true" ]]; then
      cat > "$cdir/hysteria2-obfs-warp.json" <<EOF
{
  "type": "hysteria2",
  "tag": "hysteria2-obfs-out-w",
  "server": "$ip",
  "server_port": $PORT_HY2_OBFS_W,
  "password": "$HY2_OBFS_PWD",
  "obfs": {
    "type": "salamander",
    "password": "$HY2_OBFS_PWD"
  },
  "detour": "$warp_proxy"
}
EOF
      echo -e "hysteria2://$HY2_OBFS_PWD@$ip:$PORT_HY2_OBFS_W?obfs=salamander&obfs-password=$(urlenc "$HY2_OBFS_PWD")&insecure=1#$ip-hysteria2-obfs-warp" > "$cdir/hysteria2-obfs-warp-url.txt"
    fi

    if [[ "${ENABLE_SS2022:-true}" == "true" ]]; then
      cat > "$cdir/ss2022-warp.json" <<EOF
{
  "type": "shadowsocks",
  "tag": "ss2022-out-w",
  "server": "$ip",
  "server_port": $PORT_SS2022_W,
  "method": "2022-blake3-aes-128-gcm",
  "password": "$SS2022_KEY",
  "detour": "$warp_proxy"
}
EOF
      local ss2022_b64_w=$(printf '%s' "2022-blake3-aes-128-gcm:${SS2022_KEY}" | b64enc)
      echo -e "ss://$ss2022_b64_w@$ip:$PORT_SS2022_W#$ip-ss2022-warp" > "$cdir/ss2022-warp-url.txt"
    fi

    if [[ "${ENABLE_SS:-true}" == "true" ]]; then
      cat > "$cdir/ss-warp.json" <<EOF
{
  "type": "shadowsocks",
  "tag": "ss-out-w",
  "server": "$ip",
  "server_port": $PORT_SS_W,
  "method": "aes-128-gcm",
  "password": "$SS_PWD",
  "detour": "$warp_proxy"
}
EOF
      local ss_b64_w=$(printf '%s' "aes-128-gcm:${SS_PWD}" | b64enc)
      echo -e "ss://$ss_b64_w@$ip:$PORT_SS_W#$ip-ss-warp" > "$cdir/ss-warp-url.txt"
    fi

    if [[ "${ENABLE_TUIC:-true}" == "true" ]]; then
      cat > "$cdir/tuic-warp.json" <<EOF
{
  "type": "tuic",
  "tag": "tuic-out-w",
  "server": "$ip",
  "server_port": $PORT_TUIC_W,
  "uuid": "$TUIC_UUID",
  "password": "$TUIC_PWD",
  "congestion_control": "bbr",
  "udp_relay_mode": "native",
  "zero_rtt_handshake": false,
  "heartbeat": "10s",
  "tls": {
    "enabled": true,
    "server_name": "$ip",
    "insecure": false
  },
  "detour": "$warp_proxy"
}
EOF
      echo -e "tuic://$TUIC_UUID:$TUIC_PWD@$ip:$PORT_TUIC_W?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$ip&allow_insecure=0#$ip-tuic-warp" > "$cdir/tuic-warp-url.txt"
    fi
  fi

  info "Client configurations saved to $cdir/"
}

# ===== Service Management =====
install_service(){
  cat > "/etc/systemd/system/$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=Sing-Box-Plus Service
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=$SB_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=$BIN_PATH run -c $CONF_JSON
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SYSTEMD_SERVICE"
}

uninstall_service(){
  systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null || true
  systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SYSTEMD_SERVICE"
  systemctl daemon-reload
}

# ===== Firewall =====
open_ports(){
  local ports=()
  load_ports
  for v in PORT_VLESSR PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_VMESS_WS PORT_HY2_OBFS PORT_SS2022 PORT_SS PORT_TUIC \
           PORT_VLESSR_W PORT_VLESS_GRPCR_W PORT_TROJANR_W PORT_HY2_W PORT_VMESS_WS_W PORT_HY2_OBFS_W PORT_SS2022_W PORT_SS_W PORT_TUIC_W; do
    [[ -n "${!v:-}" ]] && ports+=("${!v}")
  done
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then
    for p in "${ports[@]}"; do ufw allow "$p"; done
    ufw reload
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    for p in "${ports[@]}"; do firewall-cmd --permanent --add-port="$p/tcp"; done
    firewall-cmd --reload
  elif command -v iptables >/dev/null 2>&1; then
    for p in "${ports[@]}"; do iptables -A INPUT -p tcp --dport "$p" -j ACCEPT; done
    if command -v ip6tables >/dev/null 2>&1; then
      for p in "${ports[@]}"; do ip6tables -A INPUT -p tcp --dport "$p" -j ACCEPT; done
    fi
  else
    warn "No supported firewall tool found, please open ports manually: ${ports[*]}"
  fi
}

close_ports(){
  local ports=()
  load_ports
  for v in PORT_VLESSR PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_VMESS_WS PORT_HY2_OBFS PORT_SS2022 PORT_SS PORT_TUIC \
           PORT_VLESSR_W PORT_VLESS_GRPCR_W PORT_TROJANR_W PORT_HY2_W PORT_VMESS_WS_W PORT_HY2_OBFS_W PORT_SS2022_W PORT_SS_W PORT_TUIC_W; do
    [[ -n "${!v:-}" ]] && ports+=("${!v}")
  done
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then
    for p in "${ports[@]}"; do ufw delete allow "$p"; done
    ufw reload
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    for p in "${ports[@]}"; do firewall-cmd --permanent --delete-port="$p/tcp"; done
    firewall-cmd --reload
  elif command -v iptables >/dev/null 2>&1; then
    for p in "${ports[@]}"; do iptables -D INPUT -p tcp --dport "$p" -j ACCEPT; done
    if command -v ip6tables >/dev/null 2>&1; then
      for p in "${ports[@]}"; do ip6tables -D INPUT -p tcp --dport "$p" -j ACCEPT; done
    fi
  fi
}

# ===== Main Menu =====
main_menu(){
  while true; do
    clear
    hr
    echo -e "${C_BOLD}$SCRIPT_NAME $SCRIPT_VERSION${C_RESET}"
    hr
    echo -e "1. ${C_GREEN}Install/Reinstall${C_RESET}"
    echo -e "2. ${C_YELLOW}Update sing-box${C_RESET}"
    echo -e "3. ${C_BLUE}Start${C_RESET}"
    echo -e "4. ${C_BLUE}Stop${C_RESET}"
    echo -e "5. ${C_BLUE}Restart${C_RESET}"
    echo -e "6. ${C_CYAN}Regenerate config & clients${C_RESET}"
    echo -e "7. ${C_MAGENTA}Show client configs${C_RESET}"
    echo -e "8. ${C_YELLOW}Uninstall${C_RESET}"
    echo -e "0. ${C_RED}Exit${C_RESET}"
    hr
    read -rp "Please select [0-8]: " choice
    case "$choice" in
      1) install_all;;
      2) update_singbox;;
      3) start_service;;
      4) stop_service;;
      5) restart_service;;
      6) regen_config;;
      7) show_configs;;
      8) uninstall_all;;
      0) exit 0;;
      *) echo -e "${C_RED}Invalid option${C_RESET}"; sleep 1;;
    esac
    echo
    read -rp "Press Enter to continue..."
  done
}

install_all(){
  info "Installing dependencies..."
  sbp_bootstrap

  info "Generating ports..."
  save_all_ports

  info "Generating configuration..."
  gen_config

  info "Generating client configurations..."
  gen_clients

  info "Installing service..."
  install_service

  info "Opening firewall ports..."
  open_ports

  info "Starting service..."
  start_service

  info "Installation complete!"
}

update_singbox(){
  if [[ -x "$BIN_PATH" ]]; then
    local ver; ver=$("$BIN_PATH" version 2>/dev/null | head -n1 | awk '{print $2}' || echo "unknown")
    info "Current sing-box version: $ver"
  fi
  info "Updating sing-box..."
  sbp_bootstrap
  info "Update complete!"
  restart_service
}

start_service(){
  systemctl start "$SYSTEMD_SERVICE"
  systemctl is-active "$SYSTEMD_SERVICE" && info "Service started" || warn "Service failed to start"
}

stop_service(){
  systemctl stop "$SYSTEMD_SERVICE"
  systemctl is-active "$SYSTEMD_SERVICE" && warn "Service still running" || info "Service stopped"
}

restart_service(){
  systemctl restart "$SYSTEMD_SERVICE"
  systemctl is-active "$SYSTEMD_SERVICE" && info "Service restarted" || warn "Service failed to restart"
}

regen_config(){
  info "Regenerating configuration..."
  save_all_ports
  gen_config
  gen_clients
  info "Configuration regenerated!"
  restart_service
}

show_configs(){
  local cdir="$SB_DIR/clients"
  if [[ ! -d "$cdir" ]]; then
    warn "Client configurations not found, please run install first"
    return 1
  fi
  info "Client configurations:"
  for f in "$cdir"/*-url.txt; do
    [[ -f "$f" ]] || continue
    echo -e "${C_CYAN}$(basename "$f"):${C_RESET}"
    cat "$f"
    echo
  done
}

uninstall_all(){
  read -rp "Are you sure you want to uninstall? [y/N] " ans
  [[ "$ans" =~ [yY] ]] || return
  stop_service
  uninstall_service
  close_ports
  rm -rf "$SB_DIR" "/etc/systemd/system/$SYSTEMD_SERVICE"
  info "Uninstallation complete!"
}

# ===== Entry =====
main(){
  case "${1:-}" in
    install) install_all;;
    update) update_singbox;;
    start) start_service;;
    stop) stop_service;;
    restart) restart_service;;
    regen) regen_config;;
    show) show_configs;;
    uninstall) uninstall_all;;
    *) main_menu;;
  esac
}

# Load environment
load_env
load_ports

# Ensure basic dependencies
ensure_deps curl jq tar unzip openssl

# Run
main "$@"
