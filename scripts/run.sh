#!/bin/bash
# 便捷入口：用 lldb 自带的 python 环境跑 extract_key.py（import lldb 需要它）。
# 前提：已 bash prepare_copy.sh，且已彻底退出正常微信。
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PYP="$(lldb -P)"
echo "用 lldb 的 python 环境运行（PYTHONPATH=$PYP）"
PYTHONPATH="$PYP" /usr/bin/python3 -u "$HERE/extract_key.py" "$@"
