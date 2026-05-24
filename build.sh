#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

BIN_NAME="pizdos-scanner"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

echo "Building release..."
cargo build --release

mkdir -p "$INSTALL_DIR"
install -m 755 "target/release/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

mkdir -p db results results/state

echo
echo "Installed: $INSTALL_DIR/$BIN_NAME"
echo "Binary also available at: $ROOT/target/release/$BIN_NAME"

if ! echo ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
    echo
    echo "Add to PATH (once):"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo
echo "Examples:"
echo "  $BIN_NAME geoip-list"
echo "  $BIN_NAME geoip-scan ru"
