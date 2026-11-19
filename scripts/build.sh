#!/usr/bin/env bash
# Build routerd for Cudy TR3000 (aarch64, musl, fully static).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/root/.cargo/bin:$PATH"
export CC_aarch64_unknown_linux_musl=/opt/musl/bin/aarch64-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=/opt/musl/bin/aarch64-linux-musl-ar
export RANLIB_aarch64_unknown_linux_musl=/opt/musl/bin/aarch64-linux-musl-ranlib
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/opt/musl/bin/aarch64-linux-musl-gcc

cd "$ROOT"
# rust-embed reads assets at compile time; force the crate to rebuild so UI
# edits are always embedded.
touch src/assets.rs
cargo build --release --target aarch64-unknown-linux-musl

BIN="$ROOT/target/aarch64-unknown-linux-musl/release/routerd"
install -Dm755 "$BIN" "$ROOT/packaging/files/usr/sbin/routerd"
chmod 0755 "$ROOT/packaging/files/etc/init.d/routerd" \
           "$ROOT/packaging/files/etc/uci-defaults/99-routerd"

echo
ls -lh "$ROOT/packaging/files/usr/sbin/routerd"
file "$ROOT/packaging/files/usr/sbin/routerd"
sha256sum "$ROOT/packaging/files/usr/sbin/routerd"
