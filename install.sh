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

if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" = "0" ]; then
  say "==> Applying Linux ICMP setting: net.ipv4.ping_group_range=0 1000"
  if command -v sysctl >/dev/null 2>&1; then
    if sysctl -w net.ipv4.ping_group_range="0 1000" >/dev/null 2>&1; then
      say "==> ICMP setting applied"
    else
      say "WARNING: failed to apply sysctl ping_group_range; apply manually:"
      say "  sudo sysctl -w net.ipv4.ping_group_range=\"0 1000\""
    fi
  else
    say "WARNING: sysctl not found; apply manually:"
    say "  sudo sysctl -w net.ipv4.ping_group_range=\"0 1000\""
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

say "==> Running checks"
export PATH="$BIN_DIR:$PATH"
hash -r 2>/dev/null || true
if "$LAUNCHER" --help >/dev/null 2>&1; then
  say "==> Launcher check: OK"
else
  say "WARNING: launcher check failed; try: $LAUNCHER --help"
fi

CMD_PATH="$(command -v "$BIN_NAME" 2>/dev/null || true)"
if [ -n "$CMD_PATH" ] && [ "$CMD_PATH" != "$LAUNCHER" ]; then
  say "WARNING: first '$BIN_NAME' in PATH is not launcher:"
  say "  command -v $BIN_NAME -> $CMD_PATH"
  say "  expected -> $LAUNCHER"
  say "Run in current shell:"
  say "  hash -r"
  say "  export PATH=\"$BIN_DIR:\$PATH\""
  say "  type -a $BIN_NAME"
fi

say ""
say "Done."
say "Run from anywhere:"
say "  $BIN_NAME geoip-scan ru"
say ""
say "Data dir:"
say "  $BASE_DIR"
say ""
say "Run in current shell (recommended):"
say "  hash -r"
say "  $PATH_LINE"
say "  type -a $BIN_NAME"
if [ "$(id -u)" != "0" ] && [ "$PATH_NEEDS_REFRESH" = "1" ]; then
  say "Or reload shell profile:"
  say "  source ~/.bashrc   # or: source ~/.zshrc"
fi
