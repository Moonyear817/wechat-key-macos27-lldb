#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用抓到的密钥把微信 SQLCipher 4 数据库解密成普通 SQLite 文件。
读 ~/.config/wechat-keys.json（extract_key.py 写的）和 wechat-local-vault.json。
输出到 ~/Library/Application Support/wechat-key-macos27/decrypted/（本机私密目录）。
解密后用任意 sqlite 工具查看，例如：
    sqlite3 "<输出>/message/message_0.db" ".tables"
依赖：pycryptodome（pip3 install pycryptodome）。
"""
import os, sys, json, struct, sqlite3
from pathlib import Path
try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("缺少 pycryptodome，请先 pip3 install pycryptodome")

HOME = Path(os.path.expanduser("~"))
PAGE, RESERVE, IVL = 4096, 80, 16
KEYS_FILE = HOME / ".config" / "wechat-keys.json"
CONFIG_FILE = HOME / ".config" / "wechat-local-vault.json"
OUT_BASE = HOME / "Library" / "Application Support" / "wechat-key-macos27" / "decrypted"

ALIAS = {"message_0":"message/message_0.db","message_1":"message/message_1.db",
    "message_2":"message/message_2.db","message_3":"message/message_3.db",
    "message_fts":"message/message_fts.db","message_resource":"message/message_resource.db",
    "contact":"contact/contact.db","session":"session/session.db","sns":"sns/sns.db","favorite":"favorite/favorite.db"}

def rel_of(name):
    if name in ALIAS: return ALIAS[name]
    if name.endswith(".db") and "/" in name: return name
    return None

def decrypt_db(src: Path, dst: Path, key_hex: str):
    """SQLCipher 4 逐页解密：每页用保留区里的 IV 做 AES-256-CBC；首页前 16 字节是 salt。"""
    key = bytes.fromhex(key_hex)
    if len(key) != 32: raise ValueError("密钥必须是 32 字节")
    data = src.read_bytes()
    n = len(data) // PAGE
    if n == 0: raise ValueError("库比一页还小")
    out = bytearray()
    for pn in range(n):
        page = data[pn*PAGE:(pn+1)*PAGE]
        enc_start = 16 if pn == 0 else 0
        iv = page[PAGE-RESERVE:PAGE-RESERVE+IVL]
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(page[enc_start:PAGE-RESERVE])
        op = bytearray(PAGE)
        if pn == 0:
            op[:16] = b"SQLite format 3\x00"; op[16:16+len(dec)] = dec
            op[16:18] = struct.pack(">H", PAGE)   # 写回页大小
        else:
            op[:len(dec)] = dec
        out.extend(op)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(out)

def main():
    if not KEYS_FILE.exists():
        sys.exit(f"没有密钥文件 {KEYS_FILE}，请先运行 extract_key.py")
    keys = json.loads(KEYS_FILE.read_text())
    cfg = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    db_base = Path(cfg.get("db_base_path") or "")
    if not db_base.exists():
        sys.exit("配置里没有有效的 db_base_path，请重跑 extract_key.py")
    ok = fail = 0
    for name, key_hex in sorted(keys.items()):
        rel = rel_of(name)
        if not rel: continue
        src = db_base / rel; dst = OUT_BASE / rel
        if not src.exists(): continue
        try:
            decrypt_db(src, dst, key_hex)
            try:
                c = sqlite3.connect(str(dst))
                ntab = c.execute("select count(*) from sqlite_master where type='table'").fetchone()[0]
                c.close()
            except Exception: ntab = "?"
            print(f"OK   {name:20s} -> {dst}  ({ntab} 张表)")
            ok += 1
        except Exception as e:
            print(f"FAIL {name}: {e}"); fail += 1
    print(f"\n完成：{ok} 成功，{fail} 失败。明文库在 {OUT_BASE}")
    print("提示：明文库含完整本地隐私，不要同步、分享或拷进项目/网盘。")

if __name__ == "__main__":
    main()
