#!/usr/bin/env bash
# pizdos-scanner — one-line installer (binary + geoip + config + db + hoster lists)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/momai/pizdos-scanner/master/install.sh | sh
#
# Options (env):
#   PIZDOS_DIR=~/pizdos-scanner   — рабочая папка (config, geoip, results)
#   BIN_INSTALL=~/.local/bin      — куда положить wrapper (пусто = без PATH)
#   SKIP_MMDB=1                   — не качать GeoLite2 mmdb
#   SKIP_SUBNETS=1                — не качать subnets/*.txt
#   SKIP_PATH=1                   — не прописывать PATH в shell rc

set -eu

REPO="momai/pizdos-scanner"
BRANCH="master"
RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
RELEASE="https://github.com/${REPO}/releases/latest/download"
GEOIP_DAT="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
MMDB_CITY="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
MMDB_ASN="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

PIZDOS_DIR="${PIZDOS_DIR:-$HOME/pizdos-scanner}"
BIN_INSTALL="${BIN_INSTALL:-$HOME/.local/bin}"
BIN_NAME="pizdos-scanner"
PATH_MARKER="# pizdos-scanner installer"

SUBNET_FILES=(
  yandex-cloud.txt
  vk-cloud.txt
  regru.txt
  timeweb.txt
  selectel.txt
  all-known-hosters.txt
)

info()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m!!>\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31mERR:\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "нужна команда: $1"
}

expand_home() {
  local p="$1"
  case "$p" in
    "~") echo "$HOME" ;;
    "~/"*) echo "${HOME}/${p#~/}" ;;
    *) echo "$p" ;;
  esac
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "неподдерживаемая архитектура: $machine (нужен x86_64 или arm64)" ;;
  esac
}

download() {
  local url="$1" dest="$2"
  curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url" \
    || die "не удалось скачать: $url"
}

ensure_path_in_shell() {
  local bin_dir="$1"
  local path_line="export PATH=\"${bin_dir}:\$PATH\" ${PATH_MARKER}"
  local rc added=0

  for rc in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.zshrc"; do
    [[ -f "$rc" ]] || continue
    if grep -Fq "${PATH_MARKER}" "$rc" 2>/dev/null; then
      continue
    fi
    printf '\n%s\n' "$path_line" >> "$rc"
    info "PATH добавлен в ${rc}"
    added=1
  done

  if [[ "$added" -eq 0 ]]; then
    if echo ":$PATH:" | grep -q ":${bin_dir}:"; then
      info "PATH уже содержит ${bin_dir}"
    else
      warn "shell rc не найден — добавьте PATH вручную:"
      echo "  export PATH=\"${bin_dir}:\$PATH\""
    fi
  fi

  export PATH="${bin_dir}:$PATH"
}

write_wrapper() {
  local bin_dir="$1" work_dir="$2" wrapper="${bin_dir}/${BIN_NAME}"

  cat > "$wrapper" <<EOF
#!/usr/bin/env bash
# ${PATH_MARKER}
PIZDOS_DIR="${work_dir}"
cd "\$PIZDOS_DIR" || {
  echo "pizdos-scanner: каталог не найден: \$PIZDOS_DIR" >&2
  exit 1
}
exec "\$PIZDOS_DIR/${BIN_NAME}.bin" "\$@"
EOF
  chmod +x "$wrapper"
}

main() {
  need_cmd curl
  need_cmd uname
  need_cmd chmod
  need_cmd mkdir

  local arch asset tmp bin_dir work_dir
  arch="$(detect_arch)"
  asset="${BIN_NAME}-linux-${arch}"
  work_dir="$(expand_home "$PIZDOS_DIR")"
  bin_dir="$(expand_home "$BIN_INSTALL")"

  info "архитектура: ${arch}"
  info "рабочая папка: ${work_dir}"

  mkdir -p "${work_dir}/db" "${work_dir}/results/state" "${work_dir}/subnets"

  tmp="${work_dir}/.${BIN_NAME}.new"
  info "скачиваю бинарь: ${asset}"
  download "${RELEASE}/${asset}" "${tmp}"
  chmod +x "${tmp}"
  mv -f "${tmp}" "${work_dir}/${BIN_NAME}.bin"

  if [[ -n "${BIN_INSTALL}" ]]; then
    mkdir -p "${bin_dir}"
    write_wrapper "${bin_dir}" "${work_dir}"
    info "команда в PATH: ${bin_dir}/${BIN_NAME}"

    if [[ "${SKIP_PATH:-0}" != "1" ]]; then
      ensure_path_in_shell "${bin_dir}"
    else
      export PATH="${bin_dir}:$PATH"
      warn "SKIP_PATH=1 — PATH в shell rc не прописан"
    fi
  fi

  info "скачиваю geoip.dat"
  download "${GEOIP_DAT}" "${work_dir}/geoip.dat"

  info "скачиваю config.toml"
  download "${RAW}/config.toml" "${work_dir}/config.toml"

  if [[ "${SKIP_MMDB:-0}" != "1" ]]; then
    info "скачиваю GeoLite2 mmdb (ASN/City)"
    download "${MMDB_CITY}" "${work_dir}/db/GeoLite2-City.mmdb"
    download "${MMDB_ASN}" "${work_dir}/db/GeoLite2-ASN.mmdb"
  else
    warn "SKIP_MMDB=1 — mmdb пропущены"
  fi

  if [[ "${SKIP_SUBNETS:-0}" != "1" ]]; then
    info "скачиваю списки subnets/ (хостеры)"
    local f
    for f in "${SUBNET_FILES[@]}"; do
      download "${RAW}/subnets/${f}" "${work_dir}/subnets/${f}"
    done
  else
    warn "SKIP_SUBNETS=1 — subnets пропущены"
  fi

  printf '\n'
  info "готово — можно запускать без ./"
  echo
  echo "  pizdos-scanner geoip-list"
  echo "  pizdos-scanner geoip-scan ru"
  echo "  pizdos-scanner subnets subnets/yandex-cloud.txt"
  echo
  echo "  данные: ${work_dir}"
  echo

  if [[ "${SKIP_PATH:-0}" != "1" ]] && [[ -n "${BIN_INSTALL}" ]]; then
    warn "если команда не найдена в этом же окне терминала:"
    echo "  source ~/.bashrc   # или откройте новый терминал"
    echo
  fi

  if [[ "$(id -u)" -ne 0 ]]; then
    warn "для ICMP без sudo (Linux):"
    echo '  sudo sysctl -w net.ipv4.ping_group_range="0 1000"'
    echo "  в ${work_dir}/config.toml: socket_type = \"DGRAM\""
  fi
}

main "$@"
