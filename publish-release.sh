#!/usr/bin/env bash
# 发布 SuperSQLInjectionV2 三平台版本到 SoftUpdate 更新服务
# 用法: ./publish-release.sh <管理APIKey> [版本号] [服务地址]
# 管理Key获取: 服务端启动横幅 或 服务器数据目录 admin-apikey.txt
set -e
ADMIN_KEY="${1:?用法: publish-release.sh <管理APIKey> [版本] [服务地址]}"
VERSION="${2:-2.0.0}"
SERVER="${3:-http://soft.shack2.cn}"
APP_ID="supersqlinjection"
APP_NAME="SuperSQLInjectionV2"
CHANNEL="stable"
BASE="$(cd "$(dirname "$0")" && pwd)"
REL_DIR="$BASE/release/$VERSION"

echo "== 目标服务: $SERVER  应用: $APP_ID  版本: $VERSION =="

# 1. 注册应用（已存在时 409 忽略）
code=$(curl -s -o /tmp/reg.json -w "%{http_code}" -X POST "$SERVER/api/admin/apps" \
  -H "X-Api-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{\"appId\":\"$APP_ID\",\"name\":\"$APP_NAME\",\"channel\":\"$CHANNEL\"}")
echo "注册应用: HTTP $code $(cat /tmp/reg.json)"
if [ "$code" != "201" ] && [ "$code" != "200" ] && [ "$code" != "409" ]; then
  echo "!! 注册失败（检查管理Key）"; exit 1
fi

# 2. 逐平台上传版本（草稿）
upload_platform() {
  local dir="$1" os="$2" arch="$3"
  echo "== 上传 $os/$arch =="
  local args=(-s -X POST "$SERVER/api/admin/releases" -H "X-Api-Key: $ADMIN_KEY"
    -F "appId=$APP_ID" -F "version=$VERSION" -F "channel=$CHANNEL"
    -F "os=$os" -F "arch=$arch" -F "mandatory=false"
    -F "notes=SuperSQLInjectionV2 $VERSION 首个正式发布（$os/$arch）：跨平台 Avalonia 重构；sqlmap 全类型检测 payload 对标；标记体系统一 Encode 位置推断；注入记录结构化重烘焙；多库取数/文件/命令全链路")
  local count=0
  while IFS= read -r f; do
    local rel="${f#$dir/}"
    args+=(-F "files=@$f;filename=$rel")
    count=$((count+1))
  done < <(find "$dir" -type f)
  echo "  文件数: $count"
  local resp
  resp=$(curl "${args[@]}" -w "\nHTTP:%{http_code}")
  echo "  $resp" | tail -2
  echo "$resp" | grep -q "HTTP:201\|HTTP:200" || { echo "!! $os/$arch 上传失败"; exit 1; }
}

upload_platform "$REL_DIR/win-x64" windows x64
upload_platform "$REL_DIR/linux-x64" linux x64
upload_platform "$REL_DIR/osx-arm64" osx arm64

# 3. 发布（草稿→上线）
echo "== 发布上线 =="
curl -s -H "X-Api-Key: $ADMIN_KEY" "$SERVER/api/admin/releases?appId=$APP_ID" > /tmp/releases.json
# 用 python 解析 id 列表（本版本+渠道）
ids=$(python - "$VERSION" <<'PYEOF'
import json,sys
data=json.load(open('/tmp/releases.json',encoding='utf-8'))
items=data if isinstance(data,list) else data.get('items',[])
ver=sys.argv[1]
print(' '.join(str(r['id']) for r in items if r.get('version')==ver))
PYEOF
)
for id in $ids; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SERVER/api/admin/releases/$id/publish" -H "X-Api-Key: $ADMIN_KEY")
  echo "  发布 id=$id -> HTTP $code"
done
echo "== 完成 =="
