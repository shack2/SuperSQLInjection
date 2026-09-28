#!/usr/bin/env bash
# 在 Linux（或 WSL）上编译 SuperSQLInjectionV2.Cmd 命令行的 linux-x64 Native AOT 版本。
# 依赖：.NET 10 SDK + clang + zlib1g-dev（Ubuntu: apt install clang zlib1g-dev）
# 用法：在仓库根目录执行 ./publish-cli-aot-linux.sh
set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
PUBDIR="$BASE/SuperSQLInjectionV2.Cmd/bin/Release/net10.0/linux-x64/publish"
OUTDIR="$BASE/release/2.0.0/cli-linux-x64"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "!! 本脚本必须在 Linux/WSL 上执行（Native AOT 不支持跨 OS 交叉编译）"; exit 1
fi

rm -rf "$PUBDIR"
dotnet publish "$BASE/SuperSQLInjectionV2.Cmd/SuperSQLInjectionV2.Cmd.csproj" \
  -c Release -r linux-x64 -p:PublishAot=true -p:PublishTrimmed=true

# CLI 不渲染，剔除 Avalonia 图形原生库与非 linux 平台的 quickjs 库及调试文件
rm -f "$PUBDIR"/*.pdb "$PUBDIR"/*.dbg 2>/dev/null || true
rm -f "$PUBDIR/libSkiaSharp.so" "$PUBDIR/libHarfBuzzSharp.so" \
      "$PUBDIR/libquickjs.dll" "$PUBDIR/libquickjs.dylib" 2>/dev/null || true

# 体积压缩：UPX 可压 ELF 可执行文件（共享库不支持，.so 走 strip）
if command -v upx >/dev/null 2>&1; then
  upx --best --lzma "$PUBDIR/SuperSQLInjectionV2.Cmd" || true
fi
strip "$PUBDIR/libquickjs.so" 2>/dev/null || true
command -v upx >/dev/null 2>&1 || strip "$PUBDIR/SuperSQLInjectionV2.Cmd" 2>/dev/null || true

mkdir -p "$OUTDIR"
rsync -a --delete "$PUBDIR/" "$OUTDIR/"
rm -rf "$OUTDIR/output"

echo "== linux-x64 CLI AOT 完成 =="
ls -la "$OUTDIR"
du -sh "$OUTDIR"
"$OUTDIR/SuperSQLInjectionV2.Cmd" --version
