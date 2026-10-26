#!/bin/bash
# 把 /Applications/WeChat.app 复制一份到桌面，带 get-task-allow 调试权限重新签名。
# 这样 lldb 才能附加到副本并读取它的内存（原版微信有 Hardened Runtime，附加不了）。
# 只处理你本机、你自己登录的微信。用法：bash prepare_copy.sh
set -e

SRC="/Applications/WeChat.app"
COPY="$HOME/Desktop/WeChat.app"                     # 桌面副本
HERE="$(cd "$(dirname "$0")" && pwd)"
ENT="$HERE/../entitlements.plist"

[ -d "$SRC" ] || { echo "❌ 找不到 $SRC，请先安装微信"; exit 1; }
[ -f "$ENT" ] || { echo "❌ 找不到 entitlements.plist"; exit 1; }

echo "[1/4] 退掉可能在跑的旧副本…"
pkill -f "$COPY/Contents/MacOS/WeChat" 2>/dev/null || true
sleep 3

echo "[2/4] 复制微信到桌面（APFS 克隆，几乎不占额外空间）…"
rm -rf "$COPY"
ditto "$SRC" "$COPY"

echo "[3/4] 用 get-task-allow 重新 ad-hoc 签名…"
codesign --force --deep --sign - --entitlements "$ENT" "$COPY"
xattr -dr com.apple.quarantine "$COPY" 2>/dev/null || true

echo "[4/4] 核对签名与权限…"
codesign -d --entitlements :- "$COPY" 2>/dev/null | grep -q "get-task-allow" \
  && echo "    ✅ 调试权限已写入" || { echo "❌ 权限没写进去"; exit 1; }

echo
echo "完成。副本在：$COPY"
echo "下一步：先彻底退出正常微信（⌘Q），再运行  python3 scripts/extract_key.py"
echo "（之后在弹出的桌面副本里扫码登录，密钥就会在登录那一刻被抓到）"
