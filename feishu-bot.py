#!/usr/bin/env python3
"""飞书容器管家:长连接接收命令,本地执行,原会话回显。

依赖:python3 + lark-oapi(由 run-new-api.sh 自动安装)。
配置文件 feishu-bot-config.json 与本脚本同目录:
  app_id / app_secret  飞书自建应用凭证
  owner_open_id        允许发命令的飞书用户;留空时首个发件人自动绑定并写回

status 命令直接读容器自身的 cgroup 与 /proc 数据(free/uptime 读到的是宿主机
数据,会误导),并以飞书卡片(fields 两列布局)回复;普通命令的输出以卡片
代码块回显。clash 命令回复交互卡片:两级选择策略组与节点,点击即切换
(mihomo 控制 API 127.0.0.1:9090),卡片回传交互经长连接接收。provider 与
model 命令回复下拉选择卡片,抽屉里选中即把 codex 与 codex1~codex9 全部切到所选
供应商或模型(cc-connect 管理接口 127.0.0.1:9820)。另有后台线程每分钟拉取 GitHub
部署仓库(OPS_REPO)的清单,版本变化时自动下载校验并应用,构成零浏览器额度的
自动部署通道。
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import lark_oapi as lark
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1, ReplyMessageRequest, ReplyMessageRequestBody
from lark_oapi.event.callback.model.p2_card_action_trigger import (
    P2CardActionTrigger,
    P2CardActionTriggerResponse,
)

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

    Cloud Studio 把 /proc/uptime 改写成容器自身时长,而 /proc/1/stat 的
    starttime 仍是宿主机时钟域,两者相减是两个域拼出的伪差值;容器运行
    越过两域偏移后,伪差值由负转正,能混过 [0, uptime] 检查(2026-10-14
    曾把 33 天显示成 2 天)。先用 btime + uptime ≈ now 判定两值同域:
    同域环境按 PID 1 反算容器时长,不同域直接采用 /proc/uptime。
    """
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError):
        return None
    host_domain = False
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                host_domain = abs(int(line.split()[1]) + uptime - time.time()) < 300
                break
    except (OSError, ValueError):
        pass
    if host_domain:
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


# ---------- Clash 节点切换:mihomo 控制接口 + 交互卡片 ----------
# mihomo 控制 API 监听 127.0.0.1:9090(无 secret):
#   GET /proxies        列出全部策略组与节点(Selector 组含 now 当前选中)
#   PUT /proxies/{组名}  body {"name": 节点名} 即完成切换(成功 204 空响应)
# 卡片回传交互走长连接 CARD 帧,点击到响应需在 3 秒内完成,故切换用同步短请求;
# 卡片用 2.0 结构(旧版回传交互不支持长连接),按钮 behaviors 里的 value 即回调值。

MIHOMO_API = "http://127.0.0.1:9090"
CLASH_PAGE_SIZE = 24  # 节点列表每页按钮数(2 列 x 12 行)


def mihomo_get_proxies():
    """读取 /proxies 全量数据;失败抛异常"""
    request = urllib.request.Request(MIHOMO_API + "/proxies")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8")).get("proxies", {})


def mihomo_switch(group, node):
    """切换 Selector 组的选中节点;成功时 mihomo 返回 204 空响应"""
    request = urllib.request.Request(
        MIHOMO_API + "/proxies/" + urllib.parse.quote(group, safe=""),
        data=json.dumps({"name": node}).encode("utf-8"),
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status == 204


def _callback_button(text, value, style="default"):
    """卡片 2.0 按钮;behaviors 的 callback 值会原样出现在回调事件的 action.value"""
    return {
        "tag": "button",
        "text": {"tag": "plain_text", "content": text},
        "type": style,
        "width": "fill",
        "behaviors": [{"type": "callback", "value": value}],
    }


def _button_columns(buttons):
    """一行内均分排列的按钮组"""
    return {
        "tag": "column_set",
        "flex_mode": "none",
        "columns": [
            {"tag": "column", "width": "weighted", "weight": 1, "elements": [button]}
            for button in buttons
        ],
    }


def _clash_card(title, subtitle, elements, template="blue"):
    """交互卡片统一外壳(2.0 结构),Clash 与 cc-connect 卡片共用;update_multi 让更新对所有接收者生效"""
    header = {"template": template, "title": {"tag": "plain_text", "content": title}}
    if subtitle:
        header["subtitle"] = {"tag": "plain_text", "content": subtitle}
    return {
        "schema": "2.0",
        "config": {"update_multi": True},
        "header": header,
        "body": {"elements": elements},
    }


def build_clash_group_card():
    """一级卡片:策略组清单(仅 Selector 组,GLOBAL 排除),附各组当前选中项"""
    proxies = mihomo_get_proxies()
    groups = [
        (name, info)
        for name, info in proxies.items()
        if info.get("type") == "Selector" and name != "GLOBAL"
    ]
    elements = []
    for name, info in groups:
        now = info.get("now") or "未选择"
        elements.append({
            "tag": "column_set",
            "flex_mode": "none",
            "columns": [
                {
                    "tag": "column",
                    "width": "weighted",
                    "weight": 3,
                    "vertical_align": "center",
                    "elements": [{"tag": "markdown", "content": f"**{name}**\n当前:{now}"}],
                },
                {
                    "tag": "column",
                    "width": "weighted",
                    "weight": 1,
                    "vertical_align": "center",
                    "elements": [_callback_button("切换", {"a": "g", "g": name})],
                },
            ],
        })
    if elements:
        elements.append(_button_columns([_callback_button("🔄 刷新当前状态", {"a": "b"})]))
        subtitle = f"{len(groups)} 个策略组"
    else:
        elements.append({"tag": "markdown", "content": "未发现可手动切换(Selector)的策略组。"})
        subtitle = ""
    return _clash_card("🔀 Clash 节点切换", subtitle, elements)


def build_clash_node_card(group, page=1):
    """二级卡片:指定策略组的节点按钮网格;当前节点高亮,超过一页时分页"""
    proxies = mihomo_get_proxies()
    info = proxies.get(group) or {}
    if info.get("type") != "Selector":
        return build_clash_group_card()
    nodes = list(info.get("all") or [])
    now = info.get("now") or ""
    pages = max(1, (len(nodes) + CLASH_PAGE_SIZE - 1) // CLASH_PAGE_SIZE)
    page = min(max(1, int(page or 1)), pages)
    page_nodes = nodes[(page - 1) * CLASH_PAGE_SIZE:page * CLASH_PAGE_SIZE]

    elements = []
    for i in range(0, len(page_nodes), 2):
        elements.append(_button_columns([
            _callback_button(
                node,
                {"a": "n", "g": group, "n": node},
                style="primary" if node == now else "default",
            )
            for node in page_nodes[i:i + 2]
        ]))
    nav = []
    if page > 1:
        nav.append(_callback_button("⬅️ 上一页", {"a": "p", "g": group, "p": page - 1}))
    nav.append(_callback_button("↩️ 返回", {"a": "b"}))
    if page < pages:
        nav.append(_callback_button("下一页 ➡️", {"a": "p", "g": group, "p": page + 1}))
    elements.append(_button_columns(nav))
    subtitle = f"第 {page}/{pages} 页 · 当前:{now} · 共 {len(nodes)} 项"
    return _clash_card(f"🔀 {group}", subtitle, elements)


def build_clash_result_card(group, old_now, node, ok, detail=""):
    """切换结果卡片:成功绿头/失败红头,附新旧节点与后续入口"""
    if ok:
        content = f"**{group}**\n`{old_now or '未知'}` → `{node}`"
        template, icon = "green", "✅"
    else:
        content = f"**{group}**\n切换到 `{node}` 失败\n{detail}"
        template, icon = "red", "❌"
    elements = [
        {"tag": "markdown", "content": content},
        _button_columns([
            _callback_button("↩️ 返回该组", {"a": "g", "g": group}),
            _callback_button("🔀 策略组列表", {"a": "b"}),
        ]),
    ]
    return _clash_card(f"{icon} Clash 节点切换", "", elements, template=template)


# ---------- cc-connect 供应商 / 模型一键切换 ----------
# 容器内的 cc-connect 已启用官方管理接口(配置 [management] enabled = true,
# 默认监听 127.0.0.1:9820),机器人就在容器内,可直接调用它完成供应商与模型的
# 切换;交互形态对齐 cc-connect 自带的 /provider、/model:一张卡片里放**下拉抽屉**
# (卡片 2.0 的 select_static,选项即候选项、选中即回调、当前值用 initial_option
# 预选),选中后立即生效并回报结果。区别是本机器人会把 codex 与 codex1…codex9
# 十个项目一次性切到同一项。
#   GET  /api/v1/projects/{name}/providers → {providers:[{name,active,model,…}], active_provider}
#   POST /api/v1/projects/{name}/providers/{provider}/activate
#   GET  /api/v1/projects/{name}/models    → {models:[…], current}
#   POST /api/v1/projects/{name}/model     body {"model": "…"}
# 响应统一为 {"ok": true, "data": {…}},失败为 {"ok": false, "error": "…"}。
# select_static 的回调不带 behaviors:选中值出现在事件的 action.option 字段
# (lark-oapi 的 CallBackAction.option),故选项 value 里带上类型前缀便于分派。
# 十台逐个切换远超卡片回调的 3 秒窗口,故回调只回"正在切换"卡片与提示,实际切换
# 放后台线程,完成后把结果卡片回复到原消息。

CC_CONFIG_PATH = Path(os.environ.get("CC_CONNECT_CONFIG") or "/workspace/cc-connect/config.toml")
CC_API_FALLBACK_PORT = 9820  # 配置里没写端口时的默认值(与 cc-connect 一致)
CC_PROJECTS = ("codex",) + tuple(f"codex{i}" for i in range(1, 10))  # 一键切换覆盖的项目
CC_LIST_TIMEOUT = 3  # 点击列表必须 3 秒内响应,读取列表也限制在同一窗口内
cc_switch_lock = threading.Lock()  # 同一时刻只允许一个批量切换任务
# 显式绕开代理:管理接口就在本机回环地址上,而容器里常有 http_proxy/all_proxy
# 之类的环境变量(clash 与 cc-connect 都在用代理),代理一旦不直连回环地址,
# urlopen 就会把 127.0.0.1 的请求绕出去,表现为莫名的 502/超时。
cc_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def cc_management_endpoint():
    """从 cc-connect 配置里解析 [management] 段的端口与令牌。

    容器内 Python 未必带 tomllib(3.11+ 才有),故按行解析:只认顶格
    [management] 段内的键,避免误取其它段的同名键。令牌属敏感值,只在
    内存中用于请求头,不写日志、不回显。
    """
    try:
        text = CC_CONFIG_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"读取 cc-connect 配置失败:{CC_CONFIG_PATH}({error})") from error
    port = CC_API_FALLBACK_PORT
    token = ""
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == "[management]"
            continue
        if not in_section or "=" not in stripped:
            continue
        key, _, raw = stripped.partition("=")
        value = raw.split("#")[0].strip().strip('"').strip("'")
        if key.strip() == "port" and value.isdigit():
            port = int(value)
        elif key.strip() == "token":
            token = value
    if not token:
        raise RuntimeError("cc-connect 未启用管理接口(配置 [management] 段缺少 token)")
    return port, token


def cc_api(method, path, payload=None, timeout=20):
    """调用 cc-connect 官方管理接口,返回 data 段内容;任何失败抛异常"""
    port, token = cc_management_endpoint()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with cc_opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace").strip()[:200]
        raise RuntimeError(f"HTTP {error.code}:{detail}") from error
    except OSError as error:  # 连接被拒/超时等网络错误
        raise RuntimeError(f"管理接口不可达:{error}") from error
    if not body.strip():
        return {}
    parsed = json.loads(body)
    if parsed.get("ok") is False:
        raise RuntimeError(str(parsed.get("error") or "管理接口返回失败")[:200])
    data = parsed.get("data")
    return data if isinstance(data, dict) else parsed


def cc_project_path(project):
    """项目名在 URL 路径里的安全形式(名称为数字字母,这里只做防御性转义)"""
    return urllib.parse.quote(project, safe="")


def cc_list_providers(project):
    data = cc_api(
        "GET", f"/api/v1/projects/{cc_project_path(project)}/providers", timeout=CC_LIST_TIMEOUT
    )
    return data.get("providers") or [], data.get("active_provider") or ""


def cc_list_models(project):
    data = cc_api(
        "GET", f"/api/v1/projects/{cc_project_path(project)}/models", timeout=CC_LIST_TIMEOUT
    )
    return data.get("models") or [], data.get("current") or ""


def cc_probe_project():
    """挑一个能读到供应商列表的项目作为候选项来源(codex 优先),全失败则抛异常"""
    last_error = None
    for project in CC_PROJECTS:
        try:
            cc_list_providers(project)
            return project
        except Exception as error:
            last_error = error
    raise RuntimeError(f"cc-connect 管理接口不可用:{last_error}")


def cc_switch_all(kind, value):
    """把 codex 与 codex1…codex9 逐个切到指定供应商或模型。

    顺序执行(cc-connect 每次切换都会重载对应项目),逐台返回结果供卡片如实
    展示;单台失败不影响其余项目继续,避免一台的异常中断整批操作。
    """
    results = []
    for project in CC_PROJECTS:
        path = f"/api/v1/projects/{cc_project_path(project)}"
        try:
            if kind == "provider":
                cc_api("POST", f"{path}/providers/{cc_project_path(value)}/activate")
            else:
                cc_api("POST", f"{path}/model", {"model": value})
            results.append((project, True, ""))
        except Exception as error:
            results.append((project, False, str(error)[:160]))
    return results


def _cc_select(kind, items, current):
    """供应商/模型的下拉选择组件(卡片 2.0 的 select_static)。

    选项 value 形如 "provider|anyroutertop2" / "model|gpt-6-astra":选中即回调
    (select_static 默认回传,不需要 behaviors),选中值出现在回调的
    action.option 里,自带类型前缀便于直接分派。选项 value 必须卡内唯一,
    用当前项填充 initial_option,打开抽屉时即高亮当前值。
    """
    options = [
        {"text": {"tag": "plain_text", "content": text}, "value": f"{kind}|{name}"}
        for name, text in items
    ]
    select = {
        "tag": "select_static",
        "placeholder": {"tag": "plain_text", "content": "选择 Provider" if kind == "provider" else "选择模型"},
        "options": options,
        "width": "fill",
    }
    if any(name == current for name, _ in items):
        select["initial_option"] = f"{kind}|{current}"
    return select


def build_cc_provider_card():
    """供应商卡片:一个下拉抽屉列出全部供应商,附各自的默认模型与当前选中项"""
    project = cc_probe_project()
    providers, active = cc_list_providers(project)
    items = [
        (item.get("name") or "", f"{item.get('name')}({item.get('model')})" if item.get("model") else (item.get("name") or ""))
        for item in providers
    ]
    elements = [{
        "tag": "markdown",
        "content": f"选中后立即把 **codex 及 codex1~codex9 共 {len(CC_PROJECTS)} 个项目**统一切到该供应商。",
    }]
    if items:
        elements.append(_cc_select("provider", items, active))
    else:
        elements.append({"tag": "markdown", "content": "该项目未配置任何供应商。"})
    elements.append(_button_columns([_callback_button("🔄 刷新当前状态", {"a": "cp"})]))
    return _clash_card(
        "🔌 cc-connect 供应商切换",
        f"来源:{project} · 当前:{active or '未知'} · 共 {len(items)} 项",
        elements,
    )


def build_cc_model_card():
    """模型卡片:一个下拉抽屉列出全部可用模型,当前模型为初始选中项"""
    project = cc_probe_project()
    models, current = cc_list_models(project)
    items = [(model, model) for model in models]
    elements = [{
        "tag": "markdown",
        "content": f"选中后立即把 **codex 及 codex1~codex9 共 {len(CC_PROJECTS)} 个项目**统一切到该模型。",
    }]
    if items:
        elements.append(_cc_select("model", items, current))
    else:
        elements.append({"tag": "markdown", "content": "未取得可用模型列表。"})
    elements.append(_button_columns([_callback_button("🔄 刷新当前状态", {"a": "cm"})]))
    return _clash_card(
        "🧠 cc-connect 模型切换",
        f"来源:{project} · 当前:{current or '未知'} · 共 {len(items)} 项",
        elements,
    )


def build_cc_switching_card(kind, value):
    """点击候选项后立即返回的等待卡片;真正的结果由后台线程回复"""
    label = "供应商" if kind == "provider" else "模型"
    elements = [
        {"tag": "markdown", "content": (
            f"正在把 **codex 及 codex1~codex9 共 {len(CC_PROJECTS)} 个项目**统一切到{label} `{value}`,"
            "完成后会回复一条结果卡片。"
        )},
        _button_columns([
            _callback_button("🔌 供应商列表", {"a": "cp"}),
            _callback_button("🧠 模型列表", {"a": "cm"}),
        ]),
    ]
    return _clash_card(f"⏳ 正在切换{label}:{value}", "", elements, template="orange")


def build_cc_result_card(kind, value, results):
    """批量切换结果卡片:逐台列出成功/失败,全成功绿头、部分成功橙头、全失败红头"""
    label = "供应商" if kind == "provider" else "模型"
    succeeded = sum(1 for _, ok, _ in results if ok)
    lines = [f"**{label} `{value}`** — 成功 {succeeded}/{len(results)}"]
    for project, ok, detail in results:
        lines.append(f"{'✅' if ok else '❌'} `{project}`" + (f" — {detail}" if detail else ""))
    if succeeded == len(results):
        template, icon = "green", "✅"
    elif succeeded == 0:
        template, icon = "red", "❌"
    else:
        template, icon = "orange", "⚠️"
    elements = [
        {"tag": "markdown", "content": "\n".join(lines)},
        _button_columns([
            _callback_button("🔌 供应商列表", {"a": "cp"}),
            _callback_button("🧠 模型列表", {"a": "cm"}),
        ]),
    ]
    return _clash_card(f"{icon} {label}切换结果", "", elements, template=template)


def start_cc_switch(api_client, message_id, kind, value):
    """后台执行批量切换并把结果回复到原消息;已有任务在跑时返回 False。

    卡片回调必须在 3 秒内响应,十台切换做不到,故回调只负责起线程。
    """
    if not cc_switch_lock.acquire(blocking=False):
        return False

    def run():
        try:
            results = cc_switch_all(kind, value)
            label = "供应商" if kind == "provider" else "模型"
            if api_client is None or not message_id:
                print(f"{label}批量切换完成:{results}", file=sys.stderr, flush=True)
                return
            card = build_cc_result_card(kind, value, results)
            if not _reply(api_client, message_id, card, "interactive"):
                lines = [f"{label} {value}:"]
                lines += [
                    f"{'成功' if ok else '失败'} {project}{(' — ' + detail) if detail else ''}"
                    for project, ok, detail in results
                ]
                build_reply(api_client, message_id, "\n".join(lines))
        except Exception as error:  # 后台线程异常必须自行兜住,否则静默丢结果
            print(f"批量切换异常: {error!r}", file=sys.stderr, flush=True)
            if api_client is not None and message_id:
                build_reply(api_client, message_id, f"批量切换失败:{error!r}")
        finally:
            cc_switch_lock.release()

    threading.Thread(target=run, daemon=True, name="cc-switch").start()
    return True


def make_card_action_handler(config, api_client=None):
    """卡片回传交互处理器:所有点击同步处理并返回新卡片(3 秒内),即点即更新"""

    def respond(card=None, toast_type=None, toast_text=None):
        payload = {}
        if toast_type:
            payload["toast"] = {"type": toast_type, "content": toast_text}
        if card is not None:
            payload["card"] = {"type": "raw", "data": card}
        return P2CardActionTriggerResponse(payload)

    def on_card_action(data: P2CardActionTrigger) -> P2CardActionTriggerResponse:
        try:
            event = data.event
            operator = event.operator.open_id if event and event.operator else ""
            owner = config.get("owner_open_id", "")
            if not owner or operator != owner:
                return respond(toast_type="error", toast_text="未授权,仅管理员可操作")
            value = (event.action.value if event and event.action else None) or {}
            action = value.get("a")
            # 下拉抽屉(select_static)选中即回调:选中值在 action.option,形如 "provider|名称"
            option = (getattr(event.action, "option", "") or "") if event and event.action else ""
            if option:
                kind, _, target = option.partition("|")
                if kind not in ("provider", "model") or not target:
                    return respond(toast_type="warning", toast_text="无法识别的选项")
                context = getattr(event, "context", None)
                message_id = getattr(context, "open_message_id", "") or ""
                if not start_cc_switch(api_client, message_id, kind, target):
                    return respond(toast_type="warning", toast_text="已有切换任务在进行中,请稍候")
                label = "供应商" if kind == "provider" else "模型"
                return respond(
                    card=build_cc_switching_card(kind, target),
                    toast_type="info",
                    toast_text=f"开始切换{label}:{target}",
                )
            if action == "b":
                return respond(card=build_clash_group_card())
            if action == "g":
                return respond(card=build_clash_node_card(value.get("g", ""), 1))
            if action == "p":
                return respond(card=build_clash_node_card(value.get("g", ""), int(value.get("p", 1))))
            if action == "n":
                group, node = value.get("g", ""), value.get("n", "")
                old_now = ""
                detail = ""
                try:
                    info = mihomo_get_proxies().get(group) or {}
                    old_now = info.get("now") or ""
                    mihomo_switch(group, node)
                except Exception as error:
                    detail = repr(error)
                # 重读实际状态确认切换是否落定
                confirmed = False
                try:
                    confirmed = (mihomo_get_proxies().get(group) or {}).get("now") == node
                except Exception:
                    pass
                card = build_clash_result_card(group, old_now, node, confirmed, detail)
                if confirmed:
                    return respond(card=card, toast_type="success", toast_text=f"已切换到 {node}")
                return respond(card=card, toast_type="error", toast_text="切换未生效,详见卡片")
            # cc-connect 供应商 / 模型:刷新当前列表
            if action == "cp":
                return respond(card=build_cc_provider_card())
            if action == "cm":
                return respond(card=build_cc_model_card())
            return respond(toast_type="warning", toast_text="未知操作")
        except Exception as error:  # 回调异常同样要在 3 秒内给出响应
            return respond(toast_type="error", toast_text=f"处理失败:{error!r}"[:80])

    return on_card_action


def install_card_frame_patch():
    """修补 lark-oapi 在长连接下丢弃 CARD 帧的问题。

    ws/client.py 的 _handle_data_frame 对 MessageType.CARD 直接 return,导致
    「卡片回传交互 card.action.trigger」注册的处理器永远不被调用(webhook
    模式不受影响)。CARD 帧与 EVENT 帧结构一致、仅头部 type 不同,把 CARD
    改写为 EVENT 即完整复用官方实现的派发与响应写回链路。升级 lark-oapi
    后需复核该行为是否已在官方版本中修复。
    """
    from lark_oapi.ws.client import Client
    from lark_oapi.ws.const import HEADER_TYPE

    if getattr(Client, "_card_frame_patch_installed", False):
        return
    original = Client._handle_data_frame

    async def patched(self, frame):
        try:
            for header in frame.headers:
                if header.key == HEADER_TYPE and header.value == "card":
                    header.value = "event"
                    break
        except Exception:
            pass
        return await original(self, frame)

    Client._handle_data_frame = patched
    Client._card_frame_patch_installed = True


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
            elif command in ("clash", "节点", "切换节点"):
                try:
                    card = build_clash_group_card()
                    if not _reply(api_client, message.message_id, card, "interactive"):
                        build_reply(api_client, message.message_id, "卡片发送失败,请检查 Clash(mihomo)是否在运行。")
                except Exception as error:
                    build_reply(api_client, message.message_id, f"读取 Clash 状态失败:{error!r}")
            # provider / model:列出候选项,点击后把 codex 及 codex1~codex9 一起切过去
            elif command.lstrip("/").lower() in ("provider", "providers", "供应商"):
                try:
                    card = build_cc_provider_card()
                    if not _reply(api_client, message.message_id, card, "interactive"):
                        build_reply(api_client, message.message_id, "卡片发送失败。")
                except Exception as error:
                    build_reply(api_client, message.message_id, f"读取供应商列表失败:{error!r}")
            elif command.lstrip("/").lower() in ("model", "models", "模型"):
                try:
                    card = build_cc_model_card()
                    if not _reply(api_client, message.message_id, card, "interactive"):
                        build_reply(api_client, message.message_id, "卡片发送失败。")
                except Exception as error:
                    build_reply(api_client, message.message_id, f"读取模型列表失败:{error!r}")
            else:
                output, returncode, elapsed = run_shell(command)
                try:
                    reply_exec_card(api_client, message.message_id, command, output, returncode, elapsed)
                except Exception as error:
                    build_reply(api_client, message.message_id, f"$ {command}\n{output}\n(卡片回复失败:{error!r})")
        except Exception as error:  # 单条消息异常不中断长连接
            print(f"处理消息异常: {error!r}", file=sys.stderr, flush=True)

    builder = lark.EventDispatcherHandler.builder("", "").register_p2_im_message_receive_v1(on_message)
    try:
        builder = builder.register_p2_card_action_trigger(make_card_action_handler(config, api_client))
    except AttributeError:
        # 旧版 lark-oapi 没有卡片回调注册能力;降级为仅消息命令,不影响既有功能
        print("当前 lark-oapi 不支持卡片回传交互,clash 卡片按钮将不可用", file=sys.stderr, flush=True)
    handler = builder.build()
    # 长连接下 lark-oapi 1.7.x 会静默丢弃 CARD 帧,打补丁后卡片回传交互才能到达
    try:
        install_card_frame_patch()
    except Exception as error:
        print(f"卡片帧补丁安装失败,卡片回传交互不可用:{error!r}", file=sys.stderr, flush=True)
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
