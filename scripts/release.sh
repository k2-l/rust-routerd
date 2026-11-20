#!/usr/bin/env bash
# 一键完成：单元测试 -> 编译 routerd Release -> 打包 ImmortalWrt 25.12.2 固件 -> 校验 -> 提交推送 -> 发布 GitHub Release
# 用法:
#   ./scripts/release.sh <tag> [options]
# 示例:
#   ./scripts/release.sh v1.0.2-beta
#   ./scripts/release.sh v1.0.2 --message "feat: 网络与终端管理优化" --stable
#   ./scripts/release.sh v1.0.2-beta --no-push   # 仅本地构建固件，不推送/不发 Release

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
	cat <<EOF
用法: $0 <tag> [选项]

选项:
  -m, --message <msg>   Git 提交信息（默认: "release: <tag>"）
  -n, --notes <text>    GitHub Release 说明（默认自动生成校验与变更摘要）
  --stable              发布为正式版（默认 tag 含 beta/bate/alpha/rc 时标记为 Pre-release）
  --prerelease          强制标记为 Pre-release
  --skip-tests          跳过单元测试
  --no-push             仅构建固件，不执行 git commit/push 与 gh release
  -h, --help            显示帮助
EOF
}

TAG=""
COMMIT_MSG=""
RELEASE_NOTES=""
PRERELEASE="auto"
SKIP_TESTS=0
NO_PUSH=0

while [ $# -gt 0 ]; do
	case "$1" in
		-m|--message) COMMIT_MSG="${2:-}"; shift 2 ;;
		-n|--notes)   RELEASE_NOTES="${2:-}"; shift 2 ;;
		--stable)     PRERELEASE="0"; shift ;;
		--prerelease) PRERELEASE="1"; shift ;;
		--skip-tests) SKIP_TESTS=1; shift ;;
		--no-push)    NO_PUSH=1; shift ;;
		-h|--help)    usage; exit 0 ;;
		-*)           echo "未知选项: $1" >&2; usage; exit 1 ;;
		*)
			if [ -z "$TAG" ]; then
				TAG="$1"
			else
				echo "多余参数: $1" >&2; usage; exit 1
			fi
			shift
			;;
	esac
done

if [ -z "$TAG" ]; then
	echo "ERROR: 请提供版本号 tag，例如: $0 v1.0.2-beta" >&2
	usage
	exit 1
fi

if [ "$PRERELEASE" = "auto" ]; then
	if echo "$TAG" | grep -Eqi '(beta|bate|alpha|rc)'; then
		PRERELEASE="1"
	else
		PRERELEASE="0"
	fi
fi

DEV_IMAGE="${DEV_IMAGE:-localhost/routerd-dev:immortalwrt-25.12-arm64}"
IB_IMAGE="${IB_IMAGE:-e0784142f8fe}"
CARGO_VOL="${CARGO_VOL:-routerd-cargo}"
TARGET_VOL="${TARGET_VOL:-routerd-target}"
IB_VOL="${IB_VOL:-routerd-ib}"
OUT_DIR="${OUT_DIR:-$ROOT/.release/$TAG}"
mkdir -p "$OUT_DIR"

echo "=== [1/4] 测试与编译 routerd (aarch64-unknown-linux-musl) ==="
TEST_CMD=""
if [ "$SKIP_TESTS" -eq 0 ]; then
	TEST_CMD="cargo test --offline --target aarch64-unknown-linux-musl && "
fi

podman run --rm --platform linux/arm64 --cap-add=NET_ADMIN \
	-v "$ROOT:/src:rw" \
	-v "$CARGO_VOL:/root/.cargo/registry:rw" \
	-v "$TARGET_VOL:/src/target:rw" \
	-w /src "$DEV_IMAGE" sh -c "
set -e
export RUSTFLAGS='-C target-feature=-crt-static -C link-arg=-Wl,--rpath=/usr/lib -C link-arg=-Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1'
${TEST_CMD}touch src/assets.rs
cargo build --release --offline --target aarch64-unknown-linux-musl
cp target/aarch64-unknown-linux-musl/release/routerd packaging/files/usr/sbin/routerd
chmod 0755 packaging/files/usr/sbin/routerd packaging/files/etc/init.d/routerd packaging/files/etc/uci-defaults/99-routerd
ls -lh packaging/files/usr/sbin/routerd
sha256sum packaging/files/usr/sbin/routerd
"

echo
echo "=== [2/4] 构建并校验 ImmortalWrt 25.12.2 固件镜像 ==="
podman run --rm \
	-v "$ROOT:/src:ro" \
	-v "$IB_VOL:/root/cudy:rw" \
	-v "$OUT_DIR:/out:rw" \
	-w /src "$IB_IMAGE" bash -c '
set -euo pipefail
./scripts/build-image.sh
IMG=$(ls -t /root/cudy/work/firmware/*sysupgrade.bin | head -1)
SIZE=$(stat -c %s "$IMG")
LIMIT=$((25 * 1024 * 1024))
if [ "$SIZE" -gt "$LIMIT" ]; then
	echo "ERROR: 固件体积 ${SIZE} 超过 25 MiB 限制" >&2
	exit 2
fi
if grep -Eq "^(luci|uhttpd|rpcd-mod-luci|rpcd-mod-rrdns)" /root/cudy/work/firmware/*.manifest; then
	echo "ERROR: 检测到残留 luci/uhttpd 软件包" >&2
	exit 3
fi
if ! grep -q "^kmod-nft-tproxy " /root/cudy/work/firmware/*.manifest; then
	echo "ERROR: 缺少 kmod-nft-tproxy" >&2
	exit 4
fi
cp "$IMG" /out/
cp /root/cudy/work/firmware/sha256sums /out/
'

BIN_FILE="$(ls -t "$OUT_DIR"/*sysupgrade.bin | head -1)"
SHA_FILE="$OUT_DIR/sha256sums"
BIN_SIZE="$(stat -f %z "$BIN_FILE" 2>/dev/null || stat -c %s "$BIN_FILE")"
BIN_MIB="$(awk "BEGIN{printf \"%.2f\", $BIN_SIZE/1048576}")"
BIN_SHA="$(grep 'sysupgrade.bin' "$SHA_FILE" | awk '{print $1}')"

echo
echo "固件产物: $BIN_FILE ($BIN_MIB MiB)"
echo "SHA-256 : $BIN_SHA"

if [ "$NO_PUSH" -eq 1 ]; then
	echo
	echo "已完成本地构建 (--no-push)，跳过 Git 提交与 GitHub Release。"
	exit 0
fi

echo
echo "=== [3/4] 提交并推送代码至 origin/main ==="
if [ -n "$(git status --porcelain)" ]; then
	git add -A
	MSG="${COMMIT_MSG:-release: $TAG}"
	git commit -m "$MSG"
fi
git push origin main

echo
echo "=== [4/4] 创建 GitHub Release ($TAG) ==="
if [ -z "$RELEASE_NOTES" ]; then
	RELEASE_NOTES="### 固件校验信息 (ImmortalWrt 25.12.2 · Cudy TR3000 v1)
- 文件名：\`$(basename "$BIN_FILE")\`
- 大小：\`${BIN_SIZE} bytes\` (\`${BIN_MIB} MiB\`)
- SHA-256：\`${BIN_SHA}\`"
fi

GH_ARGS=(
	"$TAG"
	"$BIN_FILE"
	"$SHA_FILE"
	--title "$TAG (ImmortalWrt 25.12.2 Cudy TR3000 v1)"
	--notes "$RELEASE_NOTES"
)
if [ "$PRERELEASE" = "1" ]; then
	GH_ARGS+=(--prerelease)
fi

gh release create "${GH_ARGS[@]}"
echo "发布完成!"
