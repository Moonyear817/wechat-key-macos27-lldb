---
name: wechat-key-macos27-lldb
description: |
  在 macOS 26/27（Apple 芯片）上提取微信 4.x 的 SQLCipher 数据库密钥并解密本地聊天库。
  当 frida 方案在新版 macOS 上失效（CCKeyDerivationPBKDF 挂钩报 "no instruction could be
  decoded there"、attach 读不了内存）时使用本技能：改用系统自带的 LLDB，在登录那一刻于
  PBKDF2 密钥派生函数上下断点，抓取口令并推导出全部库的 32 字节密钥。仅用于本机、用户本人
  登录的微信账号的本地数据。触发词：微信密钥、微信解密、wechat key、macOS 27 微信、
  frida 挂不上、no instruction could be decoded、lldb 取密钥、sqlcipher key。
---

# 微信密钥提取（macOS 26/27 · LLDB 法）

在新版 macOS（Tahoe 26 / 27，Apple 芯片）上，常见的 frida 方案会失败：对微信使用的
`CCKeyDerivationPBKDF` / `ccpbkdf2_hmac` / `PKCS5_PBKDF2_HMAC` 下内联钩子会报
`unable to intercept function ... no instruction could be decoded there`；换 attach 模式
即使用 root 也读不了目标进程内存（能列出内存段，每段读 0）。

本技能改用**系统自带、苹果签名、带调试权限的 LLDB**。它能附加到一个 ad-hoc 重签（加了
`get-task-allow`）的微信副本、读取其内存、并在密钥派生函数上下断点。核心是**在登录那一刻**
抓：微信登录时一次性打开所有库并做 PBKDF2 主密钥派生，断点命中时口令就在寄存器指向的内存里，
再用每个库首页的 16 字节 salt 自己推导出 32 字节密钥。

## 适用判断
- 用户要读/解密**本机、自己登录**的微信聊天库，而 frida 方案在本机 macOS 上失效。
- 本机是 macOS 26/27、Apple 芯片、微信 4.x。更老的 macOS 若 frida 能用，不必用本法。
- 绝不用于不属于用户的账号或设备；只处理官方第一个容器 `com.tencent.xinWeChat`。

## 前置条件
- 系统自带 `lldb`（装了 Command Line Tools 就有）。不需要 sudo，**不要关 SIP**。
- `pip3 install pycryptodome`。
- 运行脚本的程序需有「完全磁盘访问权限」，才能读 `~/Library/Containers/com.tencent.xinWeChat`。

## 步骤
1. **生成带调试权限的副本**：`bash scripts/prepare_copy.sh`
   —— 复制微信到桌面，用 `entitlements.plist`（含 `get-task-allow`）ad-hoc 重签。
2. **彻底退出正常微信**（⌘Q）。副本和正版同 bundle id，正版开着时副本起不来。
3. **下断点并等登录**：`bash scripts/run.sh`（内部用 `PYTHONPATH=$(lldb -P)` 跑
   `extract_key.py`）。它启动副本、lldb 附加、在三个 PBKDF2 函数下断点，然后提示你登录。
4. **在桌面副本里扫码登录**。登录触发主密钥派生 → 断点命中 → 推导并验证全部库密钥 →
   写入 `~/.config/wechat-keys.json`。
5. **解密**：`python3 scripts/decrypt_dbs.py` —— 逐页解密到
   `~/Library/Application Support/wechat-key-macos27/decrypted/`。之后用任意 sqlite 工具查询。

## 为什么必须在登录时抓（容易踩的坑）
- 登录完再附加**抓不到主派生**：消息库登录时就开好了，SQLCipher 还会缓存主密钥，正常使用
  不会重做 256000 轮的主派生，只会偶发 2 轮的二次(HMAC)派生。所以要先下断点、后登录。
- 2 轮那次断点的"口令"其实是**某个库的 32 字节主密钥**本身——可直接拿去验证；而 256000 轮
  那次的口令才是真正的 passphrase，可推导所有库。脚本两者都处理。

## 隐私与边界
- 只提取密钥到 `~/.config`，明文库放本机私密目录；不输出密钥/口令明文到日志；不把明文库
  同步、分享或拷进项目/网盘。
- lldb 附加会**暂停**副本（T 状态），脚本读完会 detach 恢复；若中途 kill 了脚本，用
  `kill -CONT <pid>` 让副本恢复。
- 仅限授权范围内使用（你自己的数据）。

技术细节、失败排查、每个 PBKDF2 函数的参数布局见 [README.md](README.md)。
