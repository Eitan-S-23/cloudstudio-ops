#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
codex-stop-heartbeat.py — 一键停止 codex1~codex9 的心跳（在 codex1 的 /cron 卡片点 enable 即执行）

做三件事（monkey-codex 项目 codex 不碰）：
  1. 读各台心跳状态；把仍在跑的逐个 pause（POST /api/v1/projects/<项目>/heartbeat/pause，
     等价 /heartbeat stop）。停止逻辑复用 codex-recovery-watch.py 的 pause_all（按文件
     路径加载，不复制代码）。
  2. 在 9 个聊天里各发一条通知。
  3. 把自己这条 cron 停掉（一次性动作，卡片回到 ⏸；需要时再点 enable 即再执行）。
     若某台 pause 失败则不自停，下一分钟自动再跑一轮重试（同 codex-recovery-watch.py）。

与「一键恢复 codex1~9 心跳」（codex-restore-heartbeat.py）对偶：
恢复是把 9 台逐个 resume，本脚本是把 9 台逐个 pause。

用法：
  python3 codex-stop-heartbeat.py             # 执行全停
  python3 codex-stop-heartbeat.py --dry-run   # 只报告将停哪些，不动
  python3 codex-stop-heartbeat.py --status    # 只看当前各台心跳状态
  python3 codex-stop-heartbeat.py --install   # 把自己登记进 jobs.json（装机用；幂等；需重启生效）
"""
import datetime
import importlib.util
import json
import os
import secrets
import subprocess
import sys

# 绝对路径写死容器内位置；测试时可设 CC_CONNECT_DIR 指到沙箱
BASE         = os.environ.get("CC_CONNECT_DIR") or "/workspace/cc-connect"
CONFIG       = BASE + "/config.toml"
DATA_DIR     = BASE + "/data"
LOG          = BASE + "/codex-stop-heartbeat.log"
BIN          = BASE + "/cc-connect"
WATCH_SCRIPT = BASE + "/codex-recovery-watch.py"
HOME_PROJECT = "codex1"                        # cron 归属与“会话键”来源的项目
SELF_MARKER  = "codex-stop-heartbeat.py"       # 本脚本自己的任务
DESCRIPTION  = "一键全停 codex1~9 心跳（卡片 enable 即执行）"

DRY = "--dry-run" in sys.argv
STATUS_ONLY = "--status" in sys.argv
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
    """按路径加载 codex-recovery-watch.py，复用它已验证的配置/状态/管理 API 逻辑"""
    spec = importlib.util.spec_from_file_location("codex_recovery_watch", WATCH_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.LOG = LOG            # 让它的日志并到本脚本的日志里
    mod.DRY = DRY
    mod.STATUS_ONLY = STATUS_ONLY
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


def home_session_key() -> str:
    """从 cron 任务表里取 codex1 的飞书会话 key（发通知、给 CLI 定项目用）"""
    for job in cron_jobs():
        if job.get("project") == HOME_PROJECT and job.get("session_key"):
            return job["session_key"]
    return ""


def cron_edit(job_id: str, field: str, value: str) -> bool:
    env = dict(os.environ, CC_PROJECT=HOME_PROJECT, CC_SESSION_KEY=home_session_key(),
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
    key = home_session_key()
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
    backup = path + ".pre-stop"
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


def main() -> int:
    if INSTALL:
        return install_job()

    w = load_watch()
    cfg = w.load_config()

    running = w.running_projects(cfg)   # None = 管理 API 不通
    if running is None:
        log("读取心跳状态失败，未做任何改动")
        return 1

    if STATUS_ONLY:
        log("运行中的心跳：" + (", ".join(running) if running else "（全部已停）"))
        return 0

    if not running:
        log("9 台心跳当前已全部处于停止状态，无需动作")
        w.notify(cfg, "⏹ codex1~codex9 的心跳当前已全部处于停止状态（无需动作）。")
        disable_self(cfg)
        return 0

    if DRY:
        log("DRY-RUN：将停掉仍在运行的心跳 —— " + ", ".join(running))
        return 0

    log("开始一键全停：仍在运行的心跳 —— " + ", ".join(running))
    failed = w.pause_all(cfg)
    if failed:
        log(f"有 {failed} 台 pause 失败，下一轮自动重试（本任务保持启用）")
        return 1

    w.notify(cfg, "⏹ 已一键停止 codex1~codex9 的心跳（等同 /heartbeat stop）。"
                  "monkey-codex 不受影响。需要再启动时，点「一键恢复 codex1~9 心跳」任务即可。")
    disable_self(cfg)
    log(f"全部 9 台心跳已停止（本次从运行中停掉：{', '.join(running)}），并已发送通知")
    return 0


if __name__ == "__main__":
    sys.exit(main())
