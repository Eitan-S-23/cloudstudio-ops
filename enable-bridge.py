#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enable-bridge.py — 启用 cc-connect 的 bridge HTTP 接口（「一键 /new」功能的前置）

背景：聊天框里手打 /new 会让 cc-connect 换一条新的会话条目（下条消息在全新
thread 上开跑）。这个动作的程序化通道是 cc-connect 原生 bridge 接口的
POST /bridge/sessions（与 /new 走同一个内部函数 NewSession）；默认配置下
bridge 是关的，本脚本做一次性启用：

  在 config.toml 的 [bridge] 段里确保三项：
    enabled = true            打开开关（缺 key 就是关的）
    port    = 9810            监听端口（缺失或 <= 0 时补默认值）
    token   = 随机生成         访问令牌（为空则生成并写入；值不外显、不打印）
  其余内容一律不动；原文件备份为 config.toml.pre-bridge；可重复执行（幂等）。
  注意：token 为空而 enabled=true 会让 cc-connect 启动即退出，所以两者一起设。

改完要重启 cc-connect 才生效（bridge 服务是启动时拉的）。

用法：
  python3 enable-bridge.py            # 启用（幂等；已启用则原样退出）
  python3 enable-bridge.py --status   # 只看状态，不修改
"""
import datetime
import os
import re
import secrets
import sys

BASE         = os.environ.get("CC_CONNECT_DIR") or "/workspace/cc-connect"
CONFIG       = BASE + "/config.toml"
SECTION      = "bridge"
PORT_DEFAULT = 9810
STATUS_ONLY  = "--status" in sys.argv


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def find_section(lines: list):
    """返回 [bridge] 段的行号区间 (start, end)；段不存在返回 (None, None)"""
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"[{SECTION}]":
            start = i
            break
    if start is None:
        return None, None
    end = start + 1
    while end < len(lines) and not lines[end].lstrip().startswith("["):
        end += 1
    return start, end


def key_name(line: str):
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=", line)
    return m.group(1) if m else None


def value_of(line, key: str):
    if line is None:
        return None
    m = re.match(rf"\s*{key}\s*=\s*(.+?)\s*$", line)
    return m.group(1) if m else None


def read_state(lines: list, start, end) -> dict:
    got = {"enabled": None, "port": None, "token": None}
    for line in lines[start:end]:
        k = key_name(line)
        if k in got and got[k] is None:
            got[k] = line
    return got


def gen_token() -> str:
    """32 位十六进制随机令牌；只写入文件，任何输出里都不出现"""
    return secrets.token_hex(16)


def main() -> int:
    if not os.path.isfile(CONFIG):
        log(f"找不到 {CONFIG}")
        return 1
    with open(CONFIG, "rb") as fh:
        raw = fh.read()
    lines = raw.decode("utf-8").split("\n")

    start, end = find_section(lines)
    state = read_state(lines, start, end) if start is not None else \
        {"enabled": None, "port": None, "token": None}

    enabled_v = (value_of(state["enabled"], "enabled") or "").lower()
    port_v = value_of(state["port"], "port")
    token_v = value_of(state["token"], "token")
    enabled_on = enabled_v == "true"
    token_set = bool(token_v) and token_v not in ('""', "''")
    port_num = int(port_v) if port_v and port_v.isdigit() else 0

    if STATUS_ONLY:
        log(f"[bridge] 段：{'存在' if start is not None else '不存在'}")
        log(f"  enabled = {enabled_v or '(缺)'}   port = {port_num or '(缺/0)'}   "
            f"token = {'已设置(不显示)' if token_set else '(缺/空)'}")
        log("以上为当前状态；整体可用性以 codex-new-session.py --dry-run 连通探测为准")
        return 0

    if enabled_on and token_set and port_num > 0:
        log("bridge 已是启用状态（enabled=true、token 已设置、端口正常），无需改动")
        return 0

    new_token = None
    if start is None:
        # 文件尾追加新段
        while lines and lines[-1] == "":
            lines.pop()
        lines.extend(["", f"[{SECTION}]", "enabled = true",
                      f"port = {PORT_DEFAULT}"])
        new_token = gen_token()
        lines.extend([f'token = "{new_token}"', ""])
    else:
        # 段内逐行编辑：只改这三个键，其余原样保留
        seg = lines[start:end]
        seen = set()
        out = []
        for line in seg:
            k = key_name(line)
            if k == "enabled":
                out.append("enabled = true")
                seen.add("enabled")
            elif k == "port":
                out.append(f"port = {port_num if port_num > 0 else PORT_DEFAULT}")
                seen.add("port")
            elif k == "token":
                if token_set:
                    out.append(line)
                else:
                    new_token = gen_token()
                    out.append(f'token = "{new_token}"')
                seen.add("token")
            else:
                out.append(line)
        if "enabled" not in seen:
            out.append("enabled = true")
        if "port" not in seen:
            out.append(f"port = {PORT_DEFAULT}")
        if "token" not in seen:
            new_token = gen_token()
            out.append(f'token = "{new_token}"')
        lines[start:end] = out

    backup = CONFIG + ".pre-bridge"
    with open(backup, "wb") as fh:
        fh.write(raw)
    tmp = CONFIG + ".pre-bridge.tmp"
    with open(tmp, "wb") as fh:
        fh.write("\n".join(lines).encode("utf-8"))
    os.replace(tmp, CONFIG)

    log(f"已启用：enabled=true、port={port_num if port_num > 0 else PORT_DEFAULT}、"
        f"token={'新生成(已写入，不回显)' if new_token else '保持原值'}")
    log(f"原文件已备份为 {os.path.basename(backup)}；重启 cc-connect 后生效")
    return 0


if __name__ == "__main__":
    sys.exit(main())
