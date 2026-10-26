# wechat-key-macos27-lldb

在 **macOS 26 / 27（Tahoe，Apple 芯片）** 上提取微信 4.x 的 SQLCipher 数据库密钥，并解密本地聊天库——当 **frida 方案已经失效**的时候。

> Extract WeChat 4.x SQLCipher database keys on macOS 26/27 (Apple Silicon) using **LLDB** instead of frida, by breakpointing the PBKDF2 key-derivation at login. For your own local, logged-in account only.

这是一套「frida 全军覆没之后，改用 LLDB 把它拿下」的方法。下面先讲**为什么**（踩过的坑），再讲**怎么用**。

---

## 背景：frida 在 macOS 27 上为什么不行

很多现成工具（包括基于 frida 的微信取密钥脚本）在老系统上没问题，但在 macOS 26/27 + Apple 芯片上会卡死。实测三条路全断：

1. **挂 PBKDF2 内联钩子**——对 `CCKeyDerivationPBKDF`（CommonCrypto）、`ccpbkdf2_hmac`（corecrypto）、`PKCS5_PBKDF2_HMAC`（OpenSSL）下 `Interceptor.attach`，全部报：
   ```
   unable to intercept function at 0x...; no instruction could be decoded there
   ```
   frida 17.x 挂不上；换 16.x 等旧版本，连注入进程都失败。
2. **挂 sqlite3_key**——系统 `libsqlite3.dylib` 的 `sqlite3_key_v2` 能挂上，但微信走的是自己打包的 `PoirotSQLite`（符号被 strip，按名字找不到），根本不调系统那个，抓到 0 条。
3. **内存扫描**——思路没问题（登录后 32 字节主密钥就在堆里，按每库 salt 验证即可）。但：spawn 模式能读内存、登录却会换主进程导致会话失效；attach 模式**即使用 sudo root 也读不了内存**（能枚举出 1.2 GB 内存段，每段 `readByteArray` 都返回 0）。

一句话：**frida 能看到的进程读不了内存，有密钥的进程又附加不上。**

## 突破：改用 LLDB

苹果自带的 `lldb` 是**苹果签名、带调试权限**的。配合把微信副本 ad-hoc 重签并加上 `get-task-allow`，lldb 能做 frida 做不到的两件事：

- **读内存**：`memory read` 直接读出真实字节（frida attach 读 0 的地方，lldb 一次读了 1.2 GB）。
- **下断点**：`breakpoint set -n CCKeyDerivationPBKDF` 解析成功——就是 frida 挂不上的那个地址 `0x...758fc`。lldb 的断点是写陷阱指令、读寄存器，和 frida 的内联钩子（要搬迁函数开头指令）机制不同，所以 frida 挂不上的它能下。

而且 **lldb 附加不需要 sudo、不用关 SIP**——`get-task-allow` + 同一用户 + 苹果签名的调试器就够了。

## 再一个坑：必须在"登录那一刻"抓

第一次在已登录的副本上下断点，只命中一次，而且是 **轮数=2、口令长度=32** 的调用——这是 SQLCipher 的**二次(HMAC)派生**，不是主派生。原因：

- 微信的消息库是**登录时**一次性打开、做 256000 轮主派生的；SQLCipher 还会缓存主密钥。登录完再附加，主派生早过去了、也不重来。
- 好在那次 2 轮调用的"口令"**恰好是某个库的 32 字节主密钥本身**——可以直接验证。但要一次拿全所有库，得抓 256000 轮的主派生。

所以正确姿势是：**先启动副本、先下断点，再扫码登录**。登录触发的主密钥派生被断点抓个正着，口令到手，用每个库的 salt 自己推导——一次还原全部 26 个库。本仓库的脚本就是这么做的。

---

## 怎么用

前置：Command Line Tools（自带 lldb）、`pip3 install pycryptodome`、给运行者「完全磁盘访问权限」。macOS 26/27、Apple 芯片、微信 4.x。

```bash
# 1) 复制微信并带 get-task-allow 重签
bash scripts/prepare_copy.sh

# 2) 彻底退出正常微信（⌘Q）——副本同 bundle id，正版开着它起不来

# 3) 启动副本、下断点、等登录
bash scripts/run.sh
#    （内部等价于： PYTHONPATH=$(lldb -P) /usr/bin/python3 scripts/extract_key.py ）

# 4) 在弹出的桌面副本里【扫码登录】。登录瞬间断点命中，密钥写入 ~/.config/wechat-keys.json

# 5) 解密到明文 SQLite
python3 scripts/decrypt_dbs.py
#    明文库在 ~/Library/Application Support/wechat-key-macos27/decrypted/
#    之后随便用 sqlite3 查：sqlite3 ".../message/message_0.db" ".tables"
```

## 原理细节

**SQLCipher 4 密钥派生**（微信 WCDB 用）：
- `main_key = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, 32)`，`salt` = 库文件首 16 字节。
- `hmac_key = PBKDF2-HMAC-SHA512(main_key, salt⊕0x3a, 2, ...)`（二次派生）。
- 每页：AES-256-CBC，IV 在页尾保留区（保留区 80 = IV 16 + HMAC-SHA512 64）。首页前 16 字节是 salt。

**断点读参数**（arm64，按函数不同）：

| 函数 | 口令指针 | 口令长度 | 轮数 | 说明 |
|---|---|---|---|---|
| `CCKeyDerivationPBKDF` | x1 | x2 | x6 | CommonCrypto 高层 API |
| `PKCS5_PBKDF2_HMAC` | x0 | x1 | x4 | OpenSSL |
| `ccpbkdf2_hmac` | x2 | x1 | x5 | corecrypto 底层 |

- 命中时若**口令长度=32**：这"口令"是某库主密钥，直接用首页验证归属。
- 若**轮数≥1024**（即 256000 主派生）：口令是真正的 passphrase，用每库 salt 推导所有库。

**验证密钥**：用候选 32 字节密钥解首页，检查还原出的 SQLite 头字段（页大小=4096、保留区=80、max/min/leaf payload = 64/32/32）。

## 失败排查
- `lldb attach 失败` → 副本没带 `get-task-allow` 重签，或正常微信还开着。重跑 `prepare_copy.sh`、退正版。
- `no instruction could be decoded`（如果你还在用 frida）→ 就是本仓库要解决的问题，改用 lldb。
- `命中但没拿到密钥` → 多半没在"扫码登录"那一刻触发，或副本是登录后才附加的。先下断点后登录。
- 副本卡住不动（T 状态）→ lldb 把它暂停了；脚本正常会 detach；若你 kill 了脚本，`kill -CONT <pid>` 恢复。
- 读不到数据目录 → 给运行者「完全磁盘访问权限」（系统设置 → 隐私与安全性）。

## 隐私与法律
- 仅用于**你自己的、本机登录的**微信账号的本地数据。不要用于不属于你的账号或设备。
- 脚本不把密钥/口令明文打到日志；明文库留在本机私密目录，**不要**同步、分享或拷进项目/网盘。
- 从他人进程内存提取密钥涉及隐私和法律问题，请在授权范围内使用，后果自负。

## 致谢
- SQLCipher 逐页解密与密钥验证的实现，参考了社区既有的微信本地解析工具的做法。
- 本仓库的独特之处：macOS 26/27 上 **frida → LLDB** 的切换，以及**预登录断点**抓主派生的流程。

## License
MIT，见 [LICENSE](LICENSE)。
