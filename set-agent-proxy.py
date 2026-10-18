#!/usr/bin/env python3
"""给 codex / claude 两个 agent 挂上 Clash 代理。

挂在哪、以及为什么不挂 run.sh:
    cc-connect 支持按 project 注入环境变量 —— [projects.agent.options] 下的 env
    子表,claudecode 与 codex 两个 agent 都读它(agent/claudecode/claudecode.go:226、
    agent/codex/codex.go:77),取值经 core.MergeEnv 覆盖同名继承项后再交给子进程。

    另一条路是往 /workspace/cc-connect/run.sh 里 source proxy.env,那样写两行就行,
    但会把 cc-connect **自己**的飞书长连接也推进 mihomo:它一挂,机器人连消息都收不到,
    你只能去网页终端看现场。走本脚本只有 codex/claude 子进程过代理,飞书通道直连 ——
    出问题至少还收得到一句"我出站全失败了"。

挂上之后是什么行为(别误解成"所有流量都走节点"):
    这两个 CLI 的出站连接全部先交给 mihomo(127.0.0.1:7890),由订阅里的规则逐条
    判定:命中 GEOIP,CN,DIRECT 的直连出去,其余走节点。省的是节点流量,不是"绕过
    内核"—— 判成直连的也一样要经过它,所以 mihomo 不在时它们会全断,不会自动退回直连。

claude / codex 认不认这些变量:
    认。两个二进制里都有 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY 的处理
    代码(claude 内含 undici 的 EnvHttpProxyAgent,codex 是 reqwest),不用额外开关。

NO_PROXY 里为什么必须有 127.0.0.1:
    codex 的 app server 模式连的是 ws://127.0.0.1:3845(agent/codex/codex.go:123),
    cc-connect 的 claude router 也在本机。这些连接走代理会直接连不上。

用法(容器内):
    python3 set-agent-proxy.py                     # 只看当前状态,不改任何文件
    python3 set-agent-proxy.py --on                # codex / claude 都挂上
    python3 set-agent-proxy.py --off               # 摘掉
    python3 set-agent-proxy.py --on --restart      # 挂上并立即重启 cc-connect 生效
    python3 set-agent-proxy.py --on --proxy http://127.0.0.1:7890

注意:重新跑 deploy-codex.sh 会重写 config.toml,本脚本写进去的 env 段会一起没掉,
      需要重跑一次本脚本。restore-all.sh 不会重写 config.toml,所以容器重启不受影响。

安全约定:改写前先用 TOML 解析器回验,解析不过绝不落盘 —— 配置写坏会让 cc-connect
    起不来,那比"代理没挂上"严重得多。
"""

import argparse
import json
import os
import pathlib
import re
import socket
import subprocess
import sys

# 输出流定死 UTF-8:本脚本要在容器(LANG 未必是 UTF-8)和用户本机(Windows 上
# python 默认按 GBK 编码 stdout)都能跑。和 set-heartbeat.py 同一处理。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

CFG_DEFAULT = "/workspace/cc-connect/config.toml"
PROC_MATCH = "^/workspace/cc-connect/cc-connect"

OPTIONS_HDR = "[projects.agent.options]"
ENV_HDR = "[projects.agent.options.env]"

# 只给这两个 agent 类型的 project 挂 —— 别的 agent(ACP/antigravity 等)没验证过,
# 不顺手改。取值是 [projects.agent] 的 type。
TARGET_TYPES = ("codex", "claudecode")

PROXY_DEFAULT = "http://127.0.0.1:7890"
SOCKS_DEFAULT = "socks5://127.0.0.1:7891"
# 与 clash-install.sh 生成的 proxy.env 保持一致,免得两处口径不同打架
NO_PROXY_DEFAULT = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


def parse_args():
    p = argparse.ArgumentParser(
        description="给 codex / claude 挂 Clash 代理(改 config.toml)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--on", action="store_true", help="挂上代理")
    p.add_argument("--off", action="store_true", help="摘掉代理")
    p.add_argument("--config", default=CFG_DEFAULT, help=f"配置文件(默认 {CFG_DEFAULT})")
    p.add_argument("--proxy", default=PROXY_DEFAULT, help=f"HTTP 代理(默认 {PROXY_DEFAULT})")
    p.add_argument("--socks", default=SOCKS_DEFAULT, help=f"SOCKS 代理(默认 {SOCKS_DEFAULT})")
    p.add_argument("--no-proxy", default=NO_PROXY_DEFAULT, help="NO_PROXY 取值")
    p.add_argument("--restart", action="store_true", help="写完立即重启 cc-connect")
    args = p.parse_args()
    if args.on and args.off:
        raise SystemExit("❌ --on 与 --off 只能给一个")
    return args


def proxy_env(args):
    """要给 agent 注入的那组变量。大写一份即可:两个 CLI 都读大写。"""
    return {
        "HTTP_PROXY": args.proxy,
        "HTTPS_PROXY": args.proxy,
        "ALL_PROXY": args.socks,
        "NO_PROXY": args.no_proxy,
    }


# ---------- 读配置 ----------
def toml_load(text):
    """优先用标准库 tomllib(3.11+);更老的 python 返回 None,由调用方降级"""
    try:
        import tomllib
    except ModuleNotFoundError:
        return None
    try:
        return tomllib.loads(text)
    except Exception as error:  # noqa: BLE001 —— 解析失败原因多样,统一报给用户
        raise SystemExit(f"❌ 现有配置文件不是合法 TOML,先修好再跑本脚本:\n   {error}")


def project_blocks(lines):
    """切出每个 [[projects]] 的文本区块,并取到它的 name。

    name 只认区块里第一个 `name =` —— 子表里的 name(如 providers.name)缩进更深,
    但简单起见还是靠"第一个"这条规则,因为生成的配置里 project 的 name 一定紧跟
    [[projects]]。
    """
    starts = [i for i, ln in enumerate(lines) if ln.strip() == "[[projects]]"]
    blocks = []
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        name = ""
        for ln in lines[start + 1:end]:
            s = ln.strip()
            if s.startswith("["):  # 越过子表头就不再找了,避免误取 providers.name
                break
            m = re.match(r'name\s*=\s*"([^"]*)"', s)
            if m:
                name = m.group(1)
                break
        blocks.append({"name": name, "start": start, "end": end})
    return blocks


def agent_type_of(lines, block):
    """读 [projects.agent] 的 type。找不到返回空串,该 project 就不在作用范围内。"""
    hdr = None
    for i in range(block["start"], block["end"]):
        if lines[i].strip() == "[projects.agent]":
            hdr = i
            break
    if hdr is None:
        return ""
    for i in range(hdr + 1, block["end"]):
        s = lines[i].strip()
        if s.startswith("["):
            break
        m = re.match(r'type\s*=\s*"([^"]*)"', s)
        if m:
            return m.group(1)
    return ""


def options_insert_at(lines, block):
    """[projects.agent.options] 直接键区的结束行号 —— env 子表该插在这里。

    必须插在选项键之后、下一个表头之前:TOML 里键的归属由"最近的表头"决定,
    插在表头紧后面会让 work_dir / mode 这些键变成 env 的子键。找不到 options
    表头时返回 None。
    """
    hdr = None
    for i in range(block["start"], block["end"]):
        if lines[i].strip() == OPTIONS_HDR:
            hdr = i
            break
    if hdr is None:
        return None
    for i in range(hdr + 1, block["end"]):
        if lines[i].strip().startswith("["):
            return i
    return block["end"]


def find_env_hdr(lines, block):
    """区块内已有的 [projects.agent.options.env] 表头行号,没有返回 None"""
    for i in range(block["start"], block["end"]):
        if lines[i].strip() == ENV_HDR:
            return i
    return None


def render_env_subtable(indent, values):
    """生成 env 子表;值用 json.dumps 转义 —— 它的转义规则与 TOML 基本字符串兼容"""
    pad = indent + "  "
    lines = [indent + ENV_HDR]
    for key in ENV_KEYS:
        lines.append(f"{pad}{key} = {json.dumps(values[key], ensure_ascii=False)}")
    return lines


def collapse_blanks(lines):
    """压掉连续空行(删段之后会留下),最多留一行"""
    out = []
    for ln in lines:
        if not ln.strip() and out and not out[-1].strip():
            continue
        out.append(ln)
    return out


def apply_to_block(lines, block, args):
    """给单个 project 区块增删 env 子表,返回 (新行列表, 动作说明或 None)"""
    atype = agent_type_of(lines, block)
    name = block["name"] or "(未命名)"
    if atype not in TARGET_TYPES:
        return lines, f"➖ {name}: type={atype or '未知'},不在本次范围"

    env_hdr = find_env_hdr(lines, block)

    if args.off:
        if env_hdr is None:
            return lines, f"➖ {name}: 本就没挂"
        stop = env_hdr + 1
        while stop < block["end"] and not lines[stop].strip().startswith("["):
            stop += 1
        return collapse_blanks(lines[:env_hdr] + lines[stop:]), f"✅ {name}: 已摘掉"

    values = proxy_env(args)
    if env_hdr is not None:
        # 已有段:整段重写(键集固定,重写比逐键改好核对)
        stop = env_hdr + 1
        while stop < block["end"] and not lines[stop].strip().startswith("["):
            stop += 1
        indent = lines[env_hdr][:len(lines[env_hdr]) - len(lines[env_hdr].lstrip())]
        return lines[:env_hdr] + render_env_subtable(indent, values) + lines[stop:], f"✅ {name}: 已更新"

    at = options_insert_at(lines, block)
    if at is None:
        return lines, f"⚠️  {name}: 没有 {OPTIONS_HDR},跳过(手工加上后再跑)"

    # 缩进跟着 options 表头走,和生成器写出来的一致
    indent = "    "
    for i in range(block["start"], block["end"]):
        if lines[i].strip() == OPTIONS_HDR:
            indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
            break
    return lines[:at] + render_env_subtable(indent, values) + lines[at:], f"✅ {name}: 已挂上"


# ---------- 回验 ----------
def verify(text, expect_on, values):
    """落盘前回验:解析得过,且目标 project 上的 env 确实是想要的那组值"""
    doc = toml_load(text)
    if doc is None:
        return "跳过回验(当前 python 无 tomllib,需 3.11+):改动已做结构性自检"
    checked = 0
    for proj in doc.get("projects", []):
        agent = proj.get("agent") or {}
        if agent.get("type") not in TARGET_TYPES:
            continue
        checked += 1
        name = proj.get("name")
        env = (agent.get("options") or {}).get("env") or {}
        if not expect_on:
            left = [k for k in ENV_KEYS if k in env]
            if left:
                raise SystemExit(f"❌ 回验失败:{name} 上还剩 {left}")
            continue
        if not env:
            raise SystemExit(f"❌ 回验失败:{name} 下没有解析出 env 段")
        for key, want in values.items():
            if env.get(key) != want:
                raise SystemExit(
                    f"❌ 回验失败:{name}.options.env.{key} 期望 {want!r},实得 {env.get(key)!r}")
    if checked == 0:
        raise SystemExit("❌ 回验失败:改写后一个 codex/claudecode project 都没有")
    return ""


def proxy_port_alive(proxy_url):
    """探一下代理端口在不在 —— 只影响提示语,判错不影响配置正确性"""
    m = re.match(r"^\w+://([^:/]+):(\d+)", proxy_url)
    if not m:
        return None
    try:
        with socket.create_connection((m.group(1), int(m.group(2))), timeout=2):
            return True
    except OSError:
        return False


# ---------- 收尾 ----------
def cc_running():
    """cc-connect 是否在跑。pgrep 不存在时按"未运行"返回,绝不让脚本崩在收尾处 ——
    那会让一次成功的改写以非零码结束,和真的失败分不开。"""
    try:
        return subprocess.run(["pgrep", "-f", PROC_MATCH],
                              capture_output=True, text=True).returncode == 0
    except (FileNotFoundError, OSError):
        return False


def report_restart(args, changed):
    if not changed:
        return 0
    if not cc_running():
        print("  ℹ️ cc-connect 当前未在运行,下次启动时生效")
        return 0
    if args.restart:
        try:
            subprocess.run(["pkill", "-f", PROC_MATCH], check=False)
            print("  🔄 已重启 cc-connect(watchdog 会在 10 秒内自动拉起)")
            return 0
        except (FileNotFoundError, OSError):
            print("  ⚠️ 找不到 pkill,请手工重启(见下)")
    print()
    print("  ⚠️ 配置改动需重启 cc-connect 才生效。加 --restart 可让本脚本代劳,")
    print("     或自己执行(会打断正在进行的对话,故没默认做):")
    print(f"     pkill -f {PROC_MATCH!r}   # watchdog 10 秒内自动拉起")
    return 0


def main():
    args = parse_args()
    cfg = pathlib.Path(args.config)
    if not cfg.is_file():
        raise SystemExit(f"❌ 找不到配置文件: {cfg}")

    text = cfg.read_text(encoding="utf-8")
    toml_load(text)  # 先确认现有配置本身是合法的,再动手
    lines = text.splitlines()
    blocks = project_blocks(lines)
    if not blocks:
        raise SystemExit(f"❌ {cfg} 里没有 [[projects]] 段")

    # 不带 --on/--off = 只读巡检
    if not args.on and not args.off:
        doc = toml_load(text)
        print(f"配置文件: {cfg}")
        print()
        for proj in (doc or {}).get("projects", []):
            agent = proj.get("agent") or {}
            env = (agent.get("options") or {}).get("env") or {}
            hit = [k for k in ENV_KEYS if k in env]
            mark = f"✅ 已挂 {env.get('HTTPS_PROXY', '')}" if hit else "➖ 未挂"
            print(f"  {proj.get('name'):<10} type={agent.get('type', '?'):<12} {mark}")
        print()
        print("挂上: python3 set-agent-proxy.py --on")
        return 0

    values = proxy_env(args)
    changed = False
    notes = []
    # 从后往前改:每轮改动只影响本区块自己的行数,而尚未处理的区块都在它**上面**,
    # 下标不受影响。正着改的话,第一个 project 一变长度,后面几个的 start/end 就
    # 全移位了 —— 拿旧下标去改会改错地方,甚至越界崩溃。
    for block in reversed(blocks):
        new_lines, note = apply_to_block(lines, block, args)
        if new_lines != lines:
            changed = True
            lines = new_lines
        if note:
            notes.append(note)
    for note in reversed(notes):
        print(f"  {note}")

    new_text = "\n".join(lines) + "\n"
    if changed:
        note = verify(new_text, args.on, values)
        # 先备份:改坏了能立刻还原,不用重新部署
        backup = cfg.with_suffix(cfg.suffix + ".bak")
        backup.write_text(text, encoding="utf-8", newline="\n")
        cfg.write_text(new_text, encoding="utf-8", newline="\n")
        # 配置里有 provider 密钥,保持创建时的收紧权限
        try:
            cfg.chmod(0o600)
        except OSError:
            pass
        print(f"     备份: {backup}")
        if note:
            print(f"     ⚠️ {note}")
        if args.on:
            alive = proxy_port_alive(args.proxy)
            if alive is False:
                print(f"  ⚠️ {args.proxy} 现在没人听 —— 先把 mihomo 拉起来,"
                      "否则这两个 agent 的出站会全部失败:")
                print("     bash /workspace/cc-connect/restore-all.sh")
    else:
        print("  (无需改动)")

    return report_restart(args, changed)


if __name__ == "__main__":
    sys.exit(main())
