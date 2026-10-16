#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
codex-new-session.py — 一键新开 codex1~codex9 的会话（在 codex1 的 /cron 卡片点 enable 即执行）

做三件事（腾讯容器-codex 项目 codex 不碰）：
  1. 把 9 台的会话上下文逐个清空（等价 /new：下次唤醒历史归零、会话不断线）。清空
     逻辑复用 rotate-codex-session.py 的既有实现（按文件路径加载，不复制代码）。
  2. 在 9 个聊天里各发一条通知。
  3. 把自己这条 cron 停掉（一次性动作，卡片回到 ⏸；需要时再点 enable 即再执行）。
     若有台正忙（agent 正在用）没能清空，则不自停，下一分钟自动再跑一轮重试。

与整点轮换的关系：轮换作业每小时对每台执行同一种清空动作（rotate-codex-session.py）；
本脚本是「手动立即全网清一遍」的卡片版：平时停用，点 enable 才执行，跑完回 ⏸。

与「一键全停 / 一键恢复 codex1~9 心跳」同族：卡片 enable 即执行 + 跑完自停用 + 失败重试。

用法：
  python3 codex-new-session.py             # 执行一键 new
  python3 codex-new-session.py --dry-run   # 只报告将清哪些，不动文件
  python3 codex-new-session.py --install   # 把自己登记进 jobs.json（装机用；幂等；需重启生效）
"""
import datetime
import importlib.util
import json
import os
import secrets
import subprocess
import sys

# 绝对路径写死容器内位置；测试时可设 CC_CONNECT_DIR 指到沙箱
BASE          = os.environ.get("CC_CONNECT_DIR") or "/workspace/cc-connect"
CONFIG        = BASE + "/config.toml"
DATA_DIR      = BASE + "/data"
LOG           = BASE + "/codex-new-session.log"
BIN           = BASE + "/cc-connect"
WATCH_SCRIPT  = BASE + "/codex-recovery-watch.py"
ROTATE_SCRIPT = BASE + "/rotate-codex-session.py"
HOME_PROJECT  = "codex1"                       # cron 归属与“会话键”来源的项目
SELF_MARKER   = "codex-new-session.py"         # 本脚本自己的任务
DESCRIPTION   = "一键 /new codex1~9 会话（卡片 enable 即执行）"
TARGETS       = [f"codex{i}" for i in range(1, 10)]

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


def load_rotate():
    """按路径加载 rotate-codex-session.py，复用它已验证的清空会话实现"""
    spec = importlib.util.spec_from_file_location("rotate_codex_session", ROTATE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
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


def main() -> int:
    if INSTALL:
        return install_job()

    r = load_rotate()
    r.DRY = DRY

    r.prune_archive()   # 与整点轮换一致：顺手清过期归档（DRY 下只打印）

    if DRY:
        for name in TARGETS:
            r.rotate_one(name)
        log("DRY-RUN 结束（以上为 9 台的预演结果，未做任何改动）")
        return 0

    busy_names, failed, cleared = [], [], []
    for name in TARGETS:
        rc, busy = r.rotate_one(name)   # 含忙检测：agent 正用着该 home 时跳过不打断
        if busy:
            busy_names.append(name)
        elif rc:
            failed.append(name)
        else:
            cleared.append(name)

    if busy_names or failed:
        parts = []
        if busy_names:
            parts.append(f"{len(busy_names)} 台正忙跳过（{', '.join(busy_names)}）")
        if failed:
            parts.append(f"{len(failed)} 台失败（{', '.join(failed)}）")
        log("未全部完成：" + "；".join(parts) + "；本任务保持启用，下一分钟自动重试")
        return 1

    w = load_watch()
    cfg = w.load_config()
    w.notify(cfg, "🆕 已一键新开会话（等同 /new）：codex1~codex9 现已全部是新会话状态。"
                  "腾讯容器-codex 不受影响。")
    disable_self(cfg)
    log(f"9 台会话已全部新开（本次实际清空 {len(cleared)} 台："
        f"{', '.join(cleared) if cleared else '均为新会话状态（无待清）'}），并已发送通知")
    return 0


if __name__ == "__main__":
    sys.exit(main())
