#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
codex-new-session.py — 一键 /new：给 codex1~codex9 全部新开会话（在 codex1 的 /cron 卡片点 enable 即执行）

做三件事（腾讯容器-codex 项目 codex 不碰）：
  1. 经 cc-connect 原生 bridge 接口 POST /bridge/sessions 给 9 台各换一条新会话
     条目——这与在聊天框里手打 /new 走的是同一个内部函数（NewSession），下一条
     消息就会在全新 thread 上跑（历史归零）；旧会话条目完整保留（/list 仍可查）。
  2. 在 9 个聊天里各发一条通知。
  3. 把自己这条 cron 停掉（一次性动作，卡片回到 ⏸；需要时再点 enable 即再执行）。
     若有台没换成功，则不自停，下一分钟自动再跑一轮重试。

前置：config.toml 的 [bridge] 段已启用（enabled=true + token）；用 enable-bridge.py
一次性完成，改完重启 cc-connect 生效。与整点轮换（rotate-codex-session.py）的关系：
轮换是“清空当前 thread 的历史”，本脚本是“换新会话条目”（与手打 /new 同一条路径），
目的相同（下轮从零开始），机制不同。

与「一键全停 / 一键恢复 codex1~9 心跳」同族：卡片 enable 即执行 + 跑完自停用 + 失败重试。

用法：
  python3 codex-new-session.py             # 执行一键 /new
  python3 codex-new-session.py --dry-run   # 只探测 bridge 与 9 台状态，不做任何改动
  python3 codex-new-session.py --install   # 把自己登记进 jobs.json（装机用；幂等；需重启生效）
"""
import datetime
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# 绝对路径写死容器内位置；测试时可设 CC_CONNECT_DIR 指到沙箱
BASE          = os.environ.get("CC_CONNECT_DIR") or "/workspace/cc-connect"
CONFIG        = BASE + "/config.toml"
DATA_DIR      = BASE + "/data"
LOG           = BASE + "/codex-new-session.log"
BIN           = BASE + "/cc-connect"
WATCH_SCRIPT  = BASE + "/codex-recovery-watch.py"
HOME_PROJECT  = "codex1"                       # cron 归属与“会话键”来源的项目
SELF_MARKER   = "codex-new-session.py"         # 本脚本自己的任务
DESCRIPTION   = "一键 /new codex1~9 会话（卡片 enable 即执行）"
TARGETS       = [f"codex{i}" for i in range(1, 10)]
HTTP_TIMEOUT  = 10

# 本地回环直连：显式绕过代理（容器全局的 HTTP_PROXY 会把 127.0.0.1 请求带进 mihomo）
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

DRY = "--dry-run" in sys.argv
INSTALL = "--install" in sys.argv


def log(msg: str) -> None:
    line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def load_watch():
    """按路径加载 codex-recovery-watch.py，复用它已验证的配置/通知逻辑"""
    spec = importlib.util.spec_from_file_location("codex_recovery_watch", WATCH_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.LOG = LOG            # 让它的日志并到本脚本的日志里
    mod.DRY = DRY
    mod.STATUS_ONLY = False
    return mod


def jobs_path() -> str:
    return os.path.join(DATA_DIR, "crons", "jobs.json")


def cron_jobs() -> list:
    try:
        with open(jobs_path(), encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return []
    return d if isinstance(d, list) else d.get("jobs", [])


def find_job(marker: str):
    return next((j for j in cron_jobs() if marker in (j.get("exec") or "")), None)


def project_session_key(name: str) -> str:
    """从 cron 任务表里取某项目的飞书会话 key（发通知、调 bridge 都用它）"""
    for job in cron_jobs():
        if job.get("project") == name and job.get("session_key"):
            return job["session_key"]
    return ""


def cron_edit(job_id: str, field: str, value: str) -> bool:
    env = dict(os.environ, CC_PROJECT=HOME_PROJECT, CC_SESSION_KEY=project_session_key(HOME_PROJECT),
               CC_DATA_DIR=DATA_DIR)
    try:
        r = subprocess.run([BIN, "cron", "edit", str(job_id), field, value],
                           capture_output=True, timeout=30, env=env)
        ok = r.returncode == 0
        echo = " ".join((r.stdout or r.stderr or b"").decode("utf-8", "replace").split())[:100]
        log(f"cron edit {job_id} {field}={value} -> rc={r.returncode} {echo}")
        return ok
    except Exception as exc:  # noqa: BLE001
        log(f"cron edit {job_id} {field}={value} 失败：{exc}")
        return False


def disable_self(cfg) -> None:
    """跑完一次后把自己这条 cron 停掉；需要时在卡片里 enable 一下就能再执行"""
    job = find_job(SELF_MARKER)
    if not job:
        log("找不到自己的 cron 任务，未停用（不影响结果）")
        return
    cron_edit(job["id"], "enabled", "false")


def install_job() -> int:
    """把本任务登记进 jobs.json（幂等：已存在即跳过）。跑完需重启 cc-connect 才生效"""
    path = jobs_path()
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    jobs = d if isinstance(d, list) else d.setdefault("jobs", [])
    if any(SELF_MARKER in (j.get("exec") or "") for j in jobs):
        log(f"任务已存在（exec 含 {SELF_MARKER}），跳过")
        return 0
    key = project_session_key(HOME_PROJECT)
    if not key:
        log(f"jobs.json 里找不到 {HOME_PROJECT} 的会话 key，无法登记")
        return 1
    job = {
        "id": secrets.token_hex(4),
        "project": HOME_PROJECT,
        "session_key": key,
        "cron_expr": "* * * * *",
        "prompt": "",
        "exec": f"/usr/bin/python3 {os.path.abspath(__file__)}",
        "description": DESCRIPTION,
        "enabled": False,
        "silent": True,
        "mute": True,
        "timeout_mins": 2,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat().replace("+00:00", "Z"),
    }
    backup = path + ".pre-new"
    with open(backup, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")
    jobs.append(job)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    log(f"已登记任务 {job['id']}（备份 {os.path.basename(backup)} 已就绪，重启 cc-connect 后生效）")
    return 0


# ---------- bridge 接口（真 /new 的通道；token 只进请求头，绝不打印） ----------

def bridge_cfg():
    """从 config.toml 的 [bridge] 段读 (port, token)。未启用/缺 token 时返回 (None, None)"""
    try:
        with open(CONFIG, "rb") as fh:
            lines = fh.read().decode("utf-8").split("\n")
    except OSError:
        return None, None
    start = None
    for i, line in enumerate(lines):
        if line.strip() == "[bridge]":
            start = i
            break
    if start is None:
        return None, None
    enabled, port, token = None, None, None
    for line in lines[start + 1:]:
        if line.lstrip().startswith("["):
            break
        m = re.match(r"\s*(enabled|port|token)\s*=\s*(.+?)\s*$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key == "enabled":
            enabled = val.lower() == "true"
        elif key == "port":
            port = int(val) if val.isdigit() else None
        else:
            token = val.strip('"').strip("'")
    if not enabled or not token or not port:
        return None, None
    return port, token


def bridge_call(port: int, token: str, method: str, path: str, body=None):
    """请求 bridge 接口。返回 (ok, data)：ok 时 data 为业务数据（容器版响应带
    {"ok","data"} 信封，这里已拆封）；否则 data 为错误描述（不含 token）。"""
    url = f"http://127.0.0.1:{port}{path}"
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=payload, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with OPENER.open(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
        parsed = json.loads(raw) if raw.strip() else {}
        # 容器版 bridge 把业务数据包了一层信封 {"ok":bool,"data":{...}}（2026-10-16 实测；
        # 失败时可能是 {"ok":false,"error":...}，没有 data 键）。凡带 ok 键即按信封
        # 拆封：成功取 data、失败判错；上游旧版直出（无 ok 键）原样返回，两种都兼容。
        if isinstance(parsed, dict) and "ok" in parsed:
            if not parsed.get("ok"):
                return False, str(parsed.get("error") or parsed.get("data") or parsed)[:500]
            return True, parsed.get("data") or {}
        return True, parsed
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:200]
        except Exception:  # noqa: BLE001
            pass
        return False, f"HTTP {exc.code} {detail}".strip()
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def new_one(port: int, token: str, name: str):
    """给一台换新会话条目（POST /bridge/sessions == 手打 /new 的同一内部函数）"""
    key = project_session_key(name)
    if not key:
        return False, "jobs.json 里找不到该项目的会话 key"
    ok, data = bridge_call(port, token, "POST", "/bridge/sessions",
                           {"session_key": key, "project": name})
    if not ok:
        return False, str(data)[:160]
    return True, f"新会话 {data.get('id', '?')}"


def probe_one(port: int, token: str, name: str):
    """只读探测一台的会话状态（--dry-run 用）"""
    key = project_session_key(name)
    if not key:
        return False, "jobs.json 里找不到该项目的会话 key"
    query = urllib.parse.urlencode({"session_key": key, "project": name})
    ok, data = bridge_call(port, token, "GET", f"/bridge/sessions?{query}")
    if not ok:
        return False, str(data)[:160]
    return True, (f"活跃会话 {data.get('active_session_id') or '(无)'}"
                  f"（共 {len(data.get('sessions') or [])} 条）")


def dry_run_probe(port: int, token: str) -> int:
    rc = 0
    for name in TARGETS:
        ok, detail = probe_one(port, token, name)
        log(f"  {name}: {detail}")
        if not ok:
            rc = 1
    if rc == 0:
        log("DRY-RUN 结束（以上为 9 台的当前会话状态，未做任何改动）")
    else:
        log("DRY-RUN 探测有失败项：bridge 未就绪或会话 key 缺失，先排查再加锁执行")
    return rc


def main() -> int:
    if INSTALL:
        return install_job()

    port, token = bridge_cfg()
    if not port:
        log("bridge 未启用：先跑一次 enable-bridge.py 并重启 cc-connect，再执行本任务")
        return 1

    if DRY:
        return dry_run_probe(port, token)

    failed, done = [], []
    for name in TARGETS:
        ok, detail = new_one(port, token, name)
        if ok:
            done.append(name)
        else:
            failed.append(f"{name}（{detail}）")

    if failed:
        log("未全部完成：" + "；".join(failed) + "；本任务保持启用，下一分钟自动重试")
        return 1

    w = load_watch()
    cfg = w.load_config()
    w.notify(cfg, "🆕 已一键 /new：codex1~codex9 已全部换到新会话（下一条消息即全新开始）。"
                  "腾讯容器-codex 不受影响。")
    disable_self(cfg)
    log(f"9 台已全部新开会话（{', '.join(done)}），并已发送通知")
    return 0


if __name__ == "__main__":
    sys.exit(main())
