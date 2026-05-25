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
install -m 755 "$TMP_BIN" "$BIN_DIR/${BIN_NAME}.bin"
rm -f "$TMP_BIN"

cat > "$BIN_DIR/$BIN_NAME" <<EOF
#!/usr/bin/env sh
set -eu

BASE_DIR="\${PIZDOS_HOME:-$BASE_DIR}"
REAL_BIN="$BIN_DIR/${BIN_NAME}.bin"

if [ ! -x "\$REAL_BIN" ]; then
  echo "ERROR: real binary not found: \$REAL_BIN" >&2
  exit 1
fi

HAS_CONFIG_ARG=0
for arg in "\$@"; do
  case "\$arg" in
    -c|--config)
      HAS_CONFIG_ARG=1
      break
      ;;
  esac
done

if [ "\$HAS_CONFIG_ARG" -eq 0 ] && [ -f "\$BASE_DIR/config.toml" ]; then
  exec "\$REAL_BIN" --config "\$BASE_DIR/config.toml" "\$@"
fi

exec "\$REAL_BIN" "\$@"
EOF
chmod 755 "$BIN_DIR/$BIN_NAME"

say "==> Downloading config + geo data"
curl -fsSL "$CONFIG_URL" -o "$BASE_DIR/config.toml"
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

say ""
say "Done."
say ""
say "Use scanner from project data dir:"
say "  cd \"$BASE_DIR\""
say "  $BIN_NAME geoip-scan ru"
say ""
say "Quick hoster scan:"
say "  cd \"$BASE_DIR\""
say "  $BIN_NAME subnets subnets/all-known-hosters.txt"
say ""
if [ "$PATH_NEEDS_REFRESH" = "1" ]; then
  say "If command is not found in current shell, run:"
  say "  $PATH_LINE"
  if [ "$(id -u)" != "0" ]; then
    say "Or reload shell profile:"
    say "  source ~/.bashrc   # or: source ~/.zshrc"
  fi
fi
