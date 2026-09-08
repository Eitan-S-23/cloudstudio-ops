#!/usr/bin/env python3
"""飞书容器管家:长连接接收命令,本地执行,原会话回显。

依赖:python3 + lark-oapi(由 run-new-api.sh 自动安装)。
配置文件 feishu-bot-config.json 与本脚本同目录:
  app_id / app_secret  飞书自建应用凭证
  owner_open_id        允许发命令的飞书用户;留空时首个发件人自动绑定并写回

status 命令直接读容器自身的 cgroup 与 /proc 数据(free/uptime 读到的是宿主机
数据,会误导),并以飞书卡片(fields 两列布局)回复;普通命令的输出以卡片
代码块回显。另有后台线程每分钟拉取 GitHub 部署仓库(OPS_REPO)的清单,
版本变化时自动下载校验并应用,构成零浏览器额度的自动部署通道。
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import lark_oapi as lark
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1, ReplyMessageRequest, ReplyMessageRequestBody

CONFIG_PATH = Path(__file__).resolve().parent / "feishu-bot-config.json"
COMMAND_TIMEOUT = 60
REPLY_CHUNK = 3500
EXEC_OUTPUT_LIMIT = 3500  # 单张卡片内命令输出的最大字符数,超长按行边界分片多卡片
MAX_EXEC_CARDS = 12  # 单命令最多回显卡片数(约 42KB),超出建议重定向文件查看
MAX_MESSAGE_AGE = 300  # 秒:超过该时限的事件(重连补发)不执行,防止重复旧命令

# 事件去重与时效:长连接重连可能重推事件,同一 event_id 只处理一次
seen_events = set()


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)


def run_shell(command, timeout=COMMAND_TIMEOUT):
    """执行 shell 命令,返回 (输出, 退出码, 耗时秒)"""
    started = time.monotonic()
    try:
        result = subprocess.run(
            ["bash", "-c", command], capture_output=True, text=True, timeout=timeout
        )
        output = ((result.stdout or "") + (result.stderr or "")).strip() or "(无输出)"
        return output, result.returncode, time.monotonic() - started
    except subprocess.TimeoutExpired:
        return f"命令超时({timeout} 秒),已终止", -1, time.monotonic() - started


# ---------- 容器状态采集:读 cgroup 与 /proc,避免 free/uptime 的宿主机数据误导 ----------

def _read_text(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _read_int(path):
    text = _read_text(path)
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _self_cgroup_v2_path():
    """/proc/self/cgroup 的 v2 行,如 0::/kubepods.slice/.../xxx.scope"""
    text = _read_text("/proc/self/cgroup")
    if text:
        for line in text.splitlines():
            if line.startswith("0::"):
                return line[3:].strip() or "/"
    return None


def _cgroup_ancestors():
    """从自身 cgroup 层到根的目录序列(自身优先,逐级向上)。

    容器内 /sys/fs/cgroup 的挂载点不一定暴露 memory.max/cpu.max
    (K8s 的限额常设在 pod 父层),沿 /proc/self/cgroup 的路径向上
    逐层查找才能拿到真实限制。
    """
    rel = _self_cgroup_v2_path()
    base = Path("/sys/fs/cgroup")
    if rel is None:
        return [base]
    parts = [part for part in rel.strip("/").split("/") if part]
    return [base.joinpath(*parts[:n]) for n in range(len(parts), 0, -1)] + [base]


def container_memory():
    """返回 (当前用量, 限额) 字节;cgroup v2 逐层向上 → v1 → (None, None)"""
    for cgroup_dir in _cgroup_ancestors():
        cur = _read_int(cgroup_dir / "memory.current")
        max_text = _read_text(cgroup_dir / "memory.max")
        if cur is not None and max_text and max_text != "max":
            try:
                limit = int(max_text)
            except ValueError:
                continue
            if 0 < limit < (1 << 50):
                return cur, limit
    cur = _read_int("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    limit = _read_int("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if cur is not None and limit is not None and limit < (1 << 50):
        return cur, limit
    return None, None


def container_cpu_cores():
    """cgroup CPU 配额(核数);沿层级向上找 cpu.max → v1 回退;未限制返回 None"""
    for cgroup_dir in _cgroup_ancestors():
        text = _read_text(cgroup_dir / "cpu.max")
        if text:
            parts = text.split()
            if len(parts) == 2 and parts[0] != "max":
                try:
                    return round(int(parts[0]) / int(parts[1]), 1)
                except (ValueError, ZeroDivisionError):
                    pass
    quota = _read_int("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    period = _read_int("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    if quota and quota > 0 and period:
        return round(quota / period, 1)
    return None


def container_uptime_seconds():
    """容器运行时长。

    /proc/uptime 在 Cloud Studio 里被虚拟化为容器自身时长,而 /proc/1/stat
    的 starttime 仍是宿主机时钟域,两者相减为负;未虚拟化的环境里 PID 1
    反算才是容器时长。先 PID 1 反算,结果落在 [0, uptime] 内才可信,
    否则直接采用 /proc/uptime 的值。
    """
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError):
        return None
    try:
        stat = Path("/proc/1/stat").read_text()
        start_ticks = int(stat.rsplit(")", 1)[1].split()[19])
        age = uptime - start_ticks / os.sysconf("SC_CLK_TCK")
        if 0 <= age <= uptime:
            return age
    except (OSError, ValueError, IndexError):
        pass
    return uptime


def find_newapi():
    """在 /proc 里找 new-api 主进程;匹配二进制路径,避免匹配到含关键字的普通命令"""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore")
        except OSError:
            continue
        if "bin/new-api" in cmdline:
            return entry.name
    return None


def format_duration(seconds):
    if seconds is None or seconds < 0:
        return "未知"
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = []
    if days:
        parts.append(f"{days} 天")
    if hours:
        parts.append(f"{hours} 小时")
    parts.append(f"{minutes} 分钟")
    return " ".join(parts)


def format_size(num):
    if num is None:
        return "未知"
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def build_status_fields():
    fields = [("运行时间", format_duration(container_uptime_seconds()))]

    cores = container_cpu_cores()
    fields.append(("CPU 配额", f"{cores:g} 核" if cores else "未限制"))

    used, limit = container_memory()
    if used is not None and limit:
        fields.append(("内存", f"{format_size(used)} / {format_size(limit)}({used * 100 / limit:.0f}%)"))
    else:
        fields.append(("内存", "cgroup 数据不可读"))

    try:
        stat = os.statvfs("/workspace")
        total = stat.f_blocks * stat.f_frsize
        avail = stat.f_bavail * stat.f_frsize
        used_disk = total - avail
        fields.append(("磁盘", f"{format_size(used_disk)} / {format_size(total)}({used_disk * 100 / total:.0f}%)"))
    except OSError:
        fields.append(("磁盘", "未知"))

    pid = find_newapi()
    fields.append(("new-api 服务", f"✅ 运行中(PID {pid})" if pid else "❌ 未运行"))
    return fields


# ---------- 消息回复 ----------

def _reply(api_client, message_id, content, msg_type):
    request = (
        ReplyMessageRequest.builder()
        .message_id(message_id)
        .request_body(
            ReplyMessageRequestBody.builder()
            .content(json.dumps(content, ensure_ascii=False))
            .msg_type(msg_type)
            .build()
        )
        .build()
    )
    response = api_client.im.v1.message.reply(request)
    if not response.success():
        print(f"回复失败: {response.code} {response.msg}", file=sys.stderr, flush=True)
    return response.success()


def build_reply(api_client, message_id, text):
    # 飞书单条文本有长度限制,分段发送
    chunks = [text[i:i + REPLY_CHUNK] for i in range(0, len(text), REPLY_CHUNK)] or ["(空)"]
    for chunk in chunks:
        _reply(api_client, message_id, {"text": chunk}, "text")


def reply_status_card(api_client, message_id):
    card = {
        "config": {"wide_screen_mode": True},
        "header": {
            "template": "blue",
            "title": {"tag": "plain_text", "content": "📊 容器状态"},
        },
        "elements": [{
            "tag": "div",
            "fields": [
                {"is_short": True, "text": {"tag": "lark_md", "content": f"**{key}**\n{value}"}}
                for key, value in build_status_fields()
            ],
        }],
    }
    # 飞书 im/v1 消息接口的 interactive 类型,content 即卡片 JSON 本身,
    # 不能再包一层 {"card": ...}(会被拒收,导致回复静默失败)。
    if not _reply(api_client, message_id, card, "interactive"):
        # 卡片被拒时降级为文本回显,保证命令永远有响应。
        lines = "\n".join(f"{key}:{value}" for key, value in build_status_fields())
        build_reply(api_client, message_id, f"📊 容器状态(卡片降级)\n{lines}")


def _split_output_by_line(output, chunk_size=EXEC_OUTPUT_LIMIT):
    """按行边界把输出切成分片;无换行的超长行退化为硬切。

    保留行完整性,避免表格/日志行被拦腰截断;分片数超过上限时
    返回 (分片列表, 截断说明)。
    """
    if len(output) <= chunk_size:
        return [output], None
    chunks = []
    start = 0
    while start < len(output) and len(chunks) < MAX_EXEC_CARDS:
        end = min(start + chunk_size, len(output))
        if end < len(output):
            newline = output.rfind("\n", start, end)
            if newline > start:
                end = newline + 1
        chunks.append(output[start:end])
        start = end
    if start < len(output):
        return chunks, f"(输出共 {len(output)} 字符,超出 {MAX_EXEC_CARDS} 张卡片上限,请重定向文件后分段查看,如:命令 > /tmp/out.txt)"
    return chunks, None


def reply_exec_card(api_client, message_id, command, output, returncode, elapsed):
    """命令执行结果以卡片回显:头部为命令,输出放 markdown 组件的代码块。

    超长输出按行边界分片为多张卡片(尾部标注 x/y),不再截断内容;输出内
    出现的 ``` 会提前闭合围栏,替换为形近字符;退出码非零时头部转红色,
    便于一眼分辨失败命令。
    """
    chunks, truncation_note = _split_output_by_line(output)
    if len(chunks) > 1:
        # 命令本体只出现在首张,后续卡片头部标注续片序号
        headers = [f"$ {command.replace(chr(10), ' ')[:60]}"] + [
            f"(续 {i}/{len(chunks)})" for i in range(2, len(chunks) + 1)
        ]
    else:
        headers = [f"$ {command.replace(chr(10), ' ')[:60]}"]
    for header, chunk in zip(headers, chunks):
        safe_output = chunk.replace("```", "ˋˋˋ")
        card = {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": "turquoise" if returncode == 0 else "red",
                "title": {"tag": "plain_text", "content": header},
            },
            "elements": [
                {
                    "tag": "markdown",
                    "content": f"**耗时 {elapsed:.1f}s · 退出码 {returncode}**\n```\n{safe_output}\n```",
                },
            ],
        }
        if not _reply(api_client, message_id, card, "interactive"):
            # 卡片被拒时降级为分片文本,保证命令永远有响应
            build_reply(api_client, message_id, f"$ {command}\n{chunk}")
            return
    if truncation_note:
        build_reply(api_client, message_id, truncation_note)


def normalize_command(raw_text):
    # 群聊里 @机器人 的消息会带 @_user_N 占位符,去掉后剩纯命令
    return re.sub(r"@_user_\d+", "", raw_text).strip()


# ---------- 自动部署通道:容器每分钟主动拉取 GitHub 公开仓库的清单 ----------
# workers.dev 域名在容器内因 DNS 污染不可达,"推"不进去;但容器出网正常,
# 让 bot 自己轮询部署仓库(内容仅部署脚本,不含任何密钥),版本变化时自动
# 下载并应用——全程零浏览器额度、零人工。双镜像源回退避免单点不可达。

OPS_REPO = "Eitan-S-23/cloudstudio-ops"
OPS_SOURCES = (
    f"https://raw.githubusercontent.com/{OPS_REPO}/main/",
    f"https://cdn.jsdelivr.net/gh/{OPS_REPO}@main/",
)
OPS_VERSION_FILE = Path(__file__).resolve().parent / ".ops-version"
OPS_POLL_SECONDS = 60


def _http_get(url, timeout=15):
    """GET 指定 URL 的字节内容;失败抛异常由调用方处理"""
    request = urllib.request.Request(url, headers={"user-agent": "feishu-bot-deploy"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _fetch_from_sources(name):
    """依次尝试各镜像源,返回第一个成功响应的内容"""
    last_error = None
    for base in OPS_SOURCES:
        try:
            return _http_get(base + name)
        except OSError as error:  # urllib 的网络错误均属 OSError 系
            last_error = error
    raise RuntimeError(f"all sources failed for {name}: {last_error!r}")


def apply_manifest(app_dir):
    """拉取部署清单;版本变化时下载文件、校验、覆盖,按需重启自身。

    清单里的 path 只允许纯文件名(防路径穿越);文件先落 .new,py 文件做
    语法编译校验,任何失败都保持原文件不动,保证容器内始终有可运行代码。
    """
    manifest = json.loads(_fetch_from_sources("manifest.json"))
    version = str(manifest.get("version", ""))
    current = OPS_VERSION_FILE.read_text().strip() if OPS_VERSION_FILE.exists() else ""
    if not version or version == current:
        return
    for item in manifest.get("files", []):
        name = item["path"]
        if "/" in name or "\\" in name or name.startswith("."):
            raise ValueError(f"invalid path in manifest: {name}")
        data = _fetch_from_sources(name)
        if hashlib.sha256(data).hexdigest() != item.get("sha256"):
            raise ValueError(f"sha256 mismatch: {name}")
        target = app_dir / name
        tmp = app_dir / f".{name}.new"
        tmp.write_bytes(data)
        if name.endswith(".py"):
            compile(tmp.read_text(encoding="utf-8"), name, "exec")
        tmp.replace(target)
    OPS_VERSION_FILE.write_text(version, encoding="utf-8")
    print(f"自动部署完成,版本 {version}", flush=True)
    if manifest.get("restart") == "bot":
        print("按清单要求重启机器人...", flush=True)
        os._exit(0)  # supervisor 会在 10 秒后拉起新代码


def deploy_loop(app_dir):
    while True:
        try:
            apply_manifest(app_dir)
        except Exception as error:
            print(f"部署轮询失败: {error!r}", file=sys.stderr, flush=True)
        time.sleep(OPS_POLL_SECONDS)


def main():
    config = load_config()
    api_client = (
        lark.Client.builder()
        .app_id(config["app_id"])
        .app_secret(config["app_secret"])
        .build()
    )

    def on_message(data: P2ImMessageReceiveV1) -> None:
        try:
            event = data.event
            # 时效过滤:创建时间过久的消息(断线重连补发)直接忽略
            create_ms = int(getattr(event.message, "create_time", 0) or 0)
            if create_ms and (int(time.time() * 1000) - create_ms) / 1000 > MAX_MESSAGE_AGE:
                return
            if data.header and data.header.event_id:
                if data.header.event_id in seen_events:
                    return
                seen_events.add(data.header.event_id)
                # 防止长期运行内存增长
                if len(seen_events) > 500:
                    seen_events.clear()

            sender = event.sender.sender_id.open_id
            message = event.message
            if message.message_type != "text":
                build_reply(api_client, message.message_id, "只支持文本命令")
                return
            command = normalize_command(json.loads(message.content).get("text", ""))
            if not command:
                return

            # 白名单:未绑定时绑定首个发件人(个人版组织内即本人),写回配置
            owner = config.get("owner_open_id", "")
            if not owner:
                config["owner_open_id"] = sender
                save_config(config)
                owner = sender
                build_reply(api_client, message.message_id, "已绑定你为管理员,此后仅响应你的命令。")
            if sender != owner:
                build_reply(api_client, message.message_id, "未授权。")
                return

            if command in ("status", "状态"):
                try:
                    reply_status_card(api_client, message.message_id)
                except Exception as error:
                    build_reply(api_client, message.message_id, f"状态采集失败:{error!r}")
            else:
                output, returncode, elapsed = run_shell(command)
                try:
                    reply_exec_card(api_client, message.message_id, command, output, returncode, elapsed)
                except Exception as error:
                    build_reply(api_client, message.message_id, f"$ {command}\n{output}\n(卡片回复失败:{error!r})")
        except Exception as error:  # 单条消息异常不中断长连接
            print(f"处理消息异常: {error!r}", file=sys.stderr, flush=True)

    handler = (
        lark.EventDispatcherHandler.builder("", "")
        .register_p2_im_message_receive_v1(on_message)
        .build()
    )
    ws_client = lark.ws.Client(
        config["app_id"],
        config["app_secret"],
        event_handler=handler,
    )
    # 自动部署轮询线程:与长连接并行,容器主动拉取更新(零浏览器额度通道)
    threading.Thread(
        target=deploy_loop,
        args=(Path(__file__).resolve().parent,),
        daemon=True,
        name="deploy",
    ).start()

    print("飞书命令机器人已启动,等待消息...", flush=True)
    ws_client.start()


if __name__ == "__main__":
    main()
