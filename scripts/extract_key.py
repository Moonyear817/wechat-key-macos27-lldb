#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用 LLDB 在"登录那一刻"抓取微信 4.x 数据库密钥（macOS 26/27 / Apple 芯片）。

为什么要这么做：
  macOS 26/27 上，frida 对微信用的 PBKDF2 系列加密函数挂不上钩子
  （报 "no instruction could be decoded there"），attach 模式即使 root 也读不了内存。
  但苹果自带、带调试权限的 LLDB 可以：既能附加、又能读内存、还能在 CCKeyDerivationPBKDF
  上下断点。微信开库时会调用它做 SQLCipher 的 PBKDF2 密钥派生——断点命中那一刻，
  "口令"(passphrase)就在寄存器指向的内存里。拿到口令，用每个库首页的 16 字节 salt
  自己做 PBKDF2-HMAC-SHA512(口令, salt, 256000, 32) 就能还原每个库的 32 字节密钥。

关键点——必须在"登录时"抓：
  微信的消息库是登录时一次性打开并派生密钥的，且 SQLCipher 会缓存主密钥。
  如果你登录完再附加，主派生早就过去了、也不会重来，只能抓到无关的二次派生。
  所以本脚本先启动副本、下好断点，再由你扫码登录——登录触发的主派生被断点抓个正着，
  一次拿全所有库。

前置：先跑  bash scripts/prepare_copy.sh  生成带 get-task-allow 的桌面副本。
依赖：系统自带 lldb；pycryptodome（pip3 install pycryptodome）。不需要 sudo、不用关 SIP。

用法：
  1) ⌘Q 彻底退出正常微信。
  2) python3 scripts/extract_key.py
  3) 在弹出的桌面副本里扫码登录；脚本抓到密钥后写入 ~/.config/wechat-keys.json。
"""
import os, sys, glob, json, struct, subprocess, hashlib, time
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("缺少 pycryptodome，请先 pip3 install pycryptodome")
try:
    import lldb  # 需用 lldb 的 python：PYTHONPATH=$(lldb -P) python3 ...（见 README / run.sh）
except ImportError:
    sys.exit("导入 lldb 失败。请用：PYTHONPATH=$(lldb -P) /usr/bin/python3 scripts/extract_key.py")

HOME = Path(os.path.expanduser("~"))
COPY = HOME / "Desktop" / "WeChat.app"
COPY_BIN = COPY / "Contents" / "MacOS" / "WeChat"
CONTAINER = HOME / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
PAGE, RESERVE, IVL = 4096, 80, 16          # SQLCipher 4：页4096，保留区80(IV16+HMAC-SHA512 64)
KDF_ITER = 256000                          # SQLCipher 4 默认轮数
KEYS_FILE = HOME / ".config" / "wechat-keys.json"
CONFIG_FILE = HOME / ".config" / "wechat-local-vault.json"

# ---- 读取本机各数据库的首页（拿 salt / IV / 首个密文块，用于验证密钥）----
def load_dbs():
    bases = glob.glob(str(CONTAINER / "*" / "db_storage"))
    if not bases:
        sys.exit("找不到微信数据目录（没登录过？容器被系统保护？确认已给运行者“完全磁盘访问权限”）")
    db_base = Path(bases[0]); wxid = db_base.parts[-2]
    dbs = {}
    for p in db_base.rglob("*.db"):
        if p.name.endswith(("-wal", "-shm")) or p.stat().st_size < PAGE:
            continue
        pg = p.read_bytes()[:PAGE]
        if len(pg) >= PAGE:
            dbs[str(p)] = pg[:16]           # path -> salt
    return db_base, wxid, dbs

def verify(path, key):
    """用首页验证 32 字节密钥是否正确（解出 SQLite 头的若干固定字段）。"""
    if len(key) != 32: return False
    pg = open(path, "rb").read(PAGE)
    iv = pg[PAGE-RESERVE:PAGE-RESERVE+IVL]
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(pg[16:16+(PAGE-RESERVE-16)])
    rb = bytearray(PAGE); rb[:16] = b"SQLite format 3\x00"; rb[16:16+len(dec)] = dec
    return (struct.unpack(">H", rb[16:18])[0] == PAGE and rb[20] == RESERVE
            and rb[21] == 64 and rb[22] == 32 and rb[23] == 32
            and rb[18] in (1, 2) and rb[19] in (1, 2))

def derive_all(dbs, pwd, rounds):
    """用口令对每个库的 salt 推导并验证。返回 {path: key_hex}。"""
    out = {}
    for path, salt in dbs.items():
        for h in ("sha512", "sha256", "sha1"):
            for r in [x for x in (rounds, KDF_ITER, 64000) if x]:
                try:
                    k = hashlib.pbkdf2_hmac(h, pwd, salt, r, 32)
                    if verify(path, k): out[path] = k.hex(); break
                except Exception: pass
            if path in out: break
    return out

# 短库名（和主流解密脚本兼容）
REL2NAME = {"message/message_0.db":"message_0","message/message_1.db":"message_1",
    "message/message_2.db":"message_2","message/message_3.db":"message_3",
    "message/message_fts.db":"message_fts","message/message_resource.db":"message_resource",
    "contact/contact.db":"contact","session/session.db":"session","sns/sns.db":"sns","favorite/favorite.db":"favorite"}

# 三个 PBKDF2 函数各自的参数寄存器下标：(口令指针, 口令长度, 轮数)
LAYOUT = {"CCKeyDerivationPBKDF": (1, 2, 6), "PKCS5_PBKDF2_HMAC": (0, 1, 4), "ccpbkdf2_hmac": (2, 1, 5)}

def ensure_copy_running():
    if not COPY_BIN.exists():
        sys.exit(f"没找到副本 {COPY}。请先运行：bash scripts/prepare_copy.sh")
    # 正常微信还开着会抢占单例，副本起不来
    if subprocess.run(["pgrep","-f","/Applications/WeChat.app/Contents/MacOS/WeChat$"],
                      capture_output=True).stdout.strip():
        sys.exit("请先彻底退出正常微信（⌘Q），再运行本脚本。")
    # 彻底退掉旧副本，等死透，再干净启动
    subprocess.run(["pkill","-f",f"{COPY}/Contents/MacOS/WeChat"])
    time.sleep(4)
    subprocess.run(["open","-n",str(COPY)])
    for _ in range(20):
        time.sleep(1)
        out = subprocess.run(["pgrep","-f",f"{COPY}/Contents/MacOS/WeChat$"],
                             capture_output=True, text=True).stdout.split()
        if out: return int(out[0])
    sys.exit("副本没能启动。")

def main():
    db_base, wxid, dbs = load_dbs()
    print(f"本机库 {len(dbs)} 个。启动签名副本…")
    pid = ensure_copy_running()
    print(f"副本 pid={pid}，附加 lldb 并下断点…")

    dbg = lldb.SBDebugger.Create(); dbg.SetAsync(False)
    target = dbg.CreateTarget(''); err = lldb.SBError()
    proc = target.AttachToProcessWithID(dbg.GetListener(), pid, err)
    if not err.Success():
        sys.exit(f"lldb 附加失败：{err.GetCString()}（副本是否带 get-task-allow 重签？）")
    for fn in LAYOUT: target.BreakpointCreateByName(fn)
    print("断点已设。\n>>> 现在请在桌面副本里【扫码登录】。登录瞬间会被断点抓到。<<<")

    def rd(a, n):
        if not a or n <= 0 or n > 8192: return b""
        e = lldb.SBError(); d = proc.ReadMemory(a, n, e)
        return d if (e.Success() and d) else b""

    found = {}; deadline = time.time() + 300; hits = 0
    while time.time() < deadline and len(found) < len(dbs):
        proc.Continue()
        if proc.GetState() == lldb.eStateExited:
            print("副本进程退出了。"); break
        th = next((t for t in proc if t.GetStopReason() == lldb.eStopReasonBreakpoint), None)
        if th is None: continue
        hits += 1
        f = th.GetFrameAtIndex(0); fname = f.GetFunctionName() or ""
        key = next((k for k in LAYOUT if k in fname), None)
        if not key: continue
        pp, pl, it = LAYOUT[key]
        def reg(i):
            r = f.FindRegister("x%d" % i); return r.GetValueAsUnsigned() if r and r.IsValid() else 0
        plen = reg(pl); iters = reg(it)
        pw = rd(reg(pp), plen if 0 < plen <= 512 else 64)
        if hits <= 50: print(f"  命中 {fname} passlen={plen} iters={iters}")
        # 32 字节的"口令"其实是某库主密钥（SQLCipher 二次派生），直接验证
        if len(pw) == 32:
            for path in dbs:
                if path not in found and verify(path, pw): found[path] = pw.hex()
        # 大轮数的那次口令=真正口令，可推导所有库
        if len(pw) >= 8 and iters >= 1024:
            found.update(derive_all(dbs, pw, iters))

    proc.Detach()

    if not found:
        print(f"\n❌ 命中 {hits} 次但没拿到密钥。请确认是在“扫码登录”这一刻触发的；可重试。")
        sys.exit(1)

    keymap = {}
    for path, hexk in found.items():
        rel = str(Path(path).relative_to(db_base))
        keymap[REL2NAME.get(rel, rel)] = hexk
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if KEYS_FILE.exists():
        try: existing = json.loads(KEYS_FILE.read_text())
        except Exception: existing = {}
    existing.update(keymap); KEYS_FILE.write_text(json.dumps(existing, indent=2))
    CONFIG_FILE.write_text(json.dumps({"wxid": wxid, "db_base_path": str(db_base)}, indent=2))
    print(f"\n✅ 成功：{len(keymap)} 个库拿到密钥，写入 {KEYS_FILE}")
    print("下一步：python3 scripts/decrypt_dbs.py  解密到明文库。")

if __name__ == "__main__":
    main()
