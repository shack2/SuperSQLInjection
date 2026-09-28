#!/usr/bin/env bash
# 在 macOS（Apple Silicon）上编译 SuperSQLInjectionV2.Cmd 命令行的 osx-arm64 Native AOT 版本。
# Native AOT 不支持跨操作系统交叉编译，必须在 macOS 本机（或 CI macos runner）执行。
# 依赖：Xcode 命令行工具（xcode-select --install）+ .NET 10 SDK。
# 用法：在仓库根目录执行 ./publish-cli-aot-osx.sh
set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
PUBDIR="$BASE/SuperSQLInjectionV2.Cmd/bin/Release/net10.0/osx-arm64/publish"
OUTDIR="$BASE/release/2.0.0/cli-osx-arm64"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "!! 本脚本必须在 macOS 上执行（Native AOT 不支持跨 OS 交叉编译）"; exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  echo "!! 当前为 $(uname -m)，osx-arm64 AOT 需在 Apple Silicon 上编译"; exit 1
fi

rm -rf "$PUBDIR"
dotnet publish "$BASE/SuperSQLInjectionV2.Cmd/SuperSQLInjectionV2.Cmd.csproj" \
  -c Release -r osx-arm64 -p:PublishAot=true -p:PublishTrimmed=true

# CLI 不渲染，剔除 Avalonia 图形原生库与非 macOS 平台的 quickjs 库
rm -f "$PUBDIR"/*.pdb "$PUBDIR"/*.dwarf 2>/dev/null || true
rm -f "$PUBDIR/libSkiaSharp.dylib" "$PUBDIR/libHarfBuzzSharp.dylib" \
      "$PUBDIR/libquickjs.dll" "$PUBDIR/libquickjs.so" 2>/dev/null || true
# strip 调试符号（UPX 不支持 macOS arm64，用 strip 裁剪）
strip "$PUBDIR/SuperSQLInjectionV2.Cmd" "$PUBDIR/libquickjs.dylib" 2>/dev/null || true

mkdir -p "$OUTDIR"
rsync -a --delete "$PUBDIR/" "$OUTDIR/"
rm -rf "$OUTDIR/output"

echo "== osx-arm64 CLI AOT 完成 =="
ls -la "$OUTDIR"
du -sh "$OUTDIR"
"$OUTDIR/SuperSQLInjectionV2.Cmd" --version
