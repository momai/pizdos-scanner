#!/usr/bin/env sh
set -eu

REPO_OWNER="momai"
REPO_NAME="pizdos-scanner"
REPO_BRANCH="master"
BIN_NAME="pizdos-scanner"

BASE_DIR="${BASE_DIR:-$HOME/.pizdos-scanner}"
if [ "$(id -u)" = "0" ]; then
  DEFAULT_BIN_DIR="/usr/local/bin"
else
  DEFAULT_BIN_DIR="$HOME/.local/bin"
fi
BIN_DIR="${BIN_DIR:-$DEFAULT_BIN_DIR}"
REAL_BIN="$BIN_DIR/${BIN_NAME}.bin"
LAUNCHER="$BIN_DIR/$BIN_NAME"

DB_DIR="$BASE_DIR/db"
SUBNETS_DIR="$BASE_DIR/subnets"

say() {
  printf '%s\n' "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    say "ERROR: required command not found: $1"
    exit 1
  fi
}

need_cmd curl
need_cmd uname
need_cmd install
need_cmd mkdir
need_cmd chmod
need_cmd grep
need_cmd id

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64)
    ARCH_SUFFIX="x86_64"
    ;;
  aarch64|arm64)
    ARCH_SUFFIX="arm64"
    ;;
  *)
    say "ERROR: unsupported architecture: $ARCH_RAW"
    say "Supported: x86_64, aarch64/arm64 (Raspberry Pi 64-bit)."
    exit 1
    ;;
esac

BIN_URL="https://github.com/$REPO_OWNER/$REPO_NAME/releases/latest/download/${BIN_NAME}-linux-${ARCH_SUFFIX}"
RAW_BASE="https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/$REPO_BRANCH"
CONFIG_URL="$RAW_BASE/config.toml"
GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
CITY_DB_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
ASN_DB_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

say "==> Installing $BIN_NAME ($ARCH_SUFFIX)"
say "==> Base dir: $BASE_DIR"
say "==> Bin dir : $BIN_DIR"

mkdir -p "$BASE_DIR" "$DB_DIR" "$SUBNETS_DIR" "$BIN_DIR" "$BASE_DIR/results/state"

TMP_BIN="$BASE_DIR/${BIN_NAME}.tmp"
curl -fsSL "$BIN_URL" -o "$TMP_BIN"
install -m 755 "$TMP_BIN" "$REAL_BIN"
rm -f "$TMP_BIN"

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env sh
set -eu

BASE_DIR="\${PIZDOS_HOME:-$BASE_DIR}"
REAL_BIN="$REAL_BIN"

if [ ! -x "\$REAL_BIN" ]; then
  echo "ERROR: real binary not found: \$REAL_BIN" >&2
  exit 1
fi

HAS_CONFIG_ARG=0
PREV_WAS_CONFIG=0
for arg in "\$@"; do
  if [ "\$PREV_WAS_CONFIG" -eq 1 ]; then
    HAS_CONFIG_ARG=1
    PREV_WAS_CONFIG=0
    continue
  fi
  case "\$arg" in
    -c|--config)
      HAS_CONFIG_ARG=1
      PREV_WAS_CONFIG=1
      ;;
    --config=*)
      HAS_CONFIG_ARG=1
      ;;
  esac
done

if [ "\$HAS_CONFIG_ARG" -eq 0 ] && [ -f "\$BASE_DIR/config.toml" ]; then
  cd "\$BASE_DIR"
  exec "\$REAL_BIN" --config "\$BASE_DIR/config.toml" "\$@"
fi

exec "\$REAL_BIN" "\$@"
EOF
chmod 755 "$LAUNCHER"

say "==> Downloading config + geo data"
if [ -f "$BASE_DIR/config.toml" ]; then
  say "==> Keeping existing config.toml"
  curl -fsSL "$CONFIG_URL" -o "$BASE_DIR/config.toml.dist"
else
  curl -fsSL "$CONFIG_URL" -o "$BASE_DIR/config.toml"
fi
curl -fsSL "$GEOIP_URL" -o "$BASE_DIR/geoip.dat"

say "==> Downloading GeoIP mmdb (optional but useful)"
curl -fsSL "$CITY_DB_URL" -o "$DB_DIR/GeoLite2-City.mmdb"
curl -fsSL "$ASN_DB_URL" -o "$DB_DIR/GeoLite2-ASN.mmdb"

say "==> Downloading hoster subnet lists"
for f in \
  yandex-cloud.txt \
  vk-cloud.txt \
  regru.txt \
  timeweb.txt \
  selectel.txt \
  all-known-hosters.txt
do
  curl -fsSL "$RAW_BASE/subnets/$f" -o "$SUBNETS_DIR/$f"
done

if [ "$(uname -s)" = "Linux" ]; then
  if command -v sysctl >/dev/null 2>&1; then
    if [ "$(id -u)" = "0" ]; then
      say "==> Applying ICMP non-root hint: net.ipv4.ping_group_range=0 1000"
      if ! sysctl -w net.ipv4.ping_group_range="0 1000" >/dev/null 2>&1; then
        say "WARNING: failed to apply net.ipv4.ping_group_range automatically"
      fi
    else
      say "==> Tip for Linux DGRAM ICMP (optional):"
      say "  sudo sysctl -w net.ipv4.ping_group_range=\"0 1000\""
    fi
  fi
fi

PATH_LINE="export PATH=\"$BIN_DIR:\$PATH\""
PATH_NEEDS_REFRESH=0
if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
  PATH_NEEDS_REFRESH=1
fi

if [ "$(id -u)" != "0" ] && [ "$PATH_NEEDS_REFRESH" = "1" ]; then
  SHELL_NAME="${SHELL##*/}"
  case "$SHELL_NAME" in
    zsh)
      PROFILE="$HOME/.zshrc"
      ;;
    bash|*)
      PROFILE="$HOME/.bashrc"
      ;;
  esac

  if [ -f "$PROFILE" ]; then
    if ! grep -Fq "$BIN_DIR" "$PROFILE"; then
      printf '\n%s\n' "$PATH_LINE" >> "$PROFILE"
      say "==> Added PATH line to $PROFILE"
    fi
  else
    printf '%s\n' "$PATH_LINE" > "$PROFILE"
    say "==> Created $PROFILE with PATH line"
  fi
fi

# NOTE: This affects only current installer process (not parent shell),
# but helps post-install checks below.
export PATH="$BIN_DIR:$PATH"

LAUNCHER_OK=0
if "$LAUNCHER" --help >/dev/null 2>&1; then
  LAUNCHER_OK=1
fi

CMD_PATH="$(command -v "$BIN_NAME" 2>/dev/null || true)"
PATH_CONFLICT=0
if [ -n "$CMD_PATH" ] && [ "$CMD_PATH" != "$LAUNCHER" ]; then
  PATH_CONFLICT=1
fi

say ""
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$LAUNCHER_OK" = "1" ]; then
  say " ✓  pizdos-scanner установлен успешно"
else
  say " ✗  Установка завершена, но launcher не ответил"
fi
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say ""
say "  Бинарь    $REAL_BIN"
say "  Launcher  $LAUNCHER"
say "  Данные    $BASE_DIR"
say ""
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say " Выполните в текущей сессии (1 раз):"
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say ""
say "  hash -r"
say "  export PATH=\"$BIN_DIR:\$PATH\""
say ""
if [ "$PATH_CONFLICT" = "1" ]; then
  say "  ⚠  В PATH есть старый бинарь: $CMD_PATH"
  say "     После hash -r он будет перекрыт новым."
  say ""
fi
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say " После этого запускайте откуда угодно:"
say "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
say ""
say "  pizdos-scanner geoip-scan ru"
say "  pizdos-scanner subnets subnets/all-known-hosters.txt"
say ""
if [ "$(id -u)" != "0" ] && [ "$PATH_NEEDS_REFRESH" = "1" ]; then
  say "  Для постоянного эффекта (уже добавлено в профиль, но применится в следующей сессии):"
  say "  source ~/.bashrc"
  say ""
fi
