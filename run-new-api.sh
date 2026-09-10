#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP_DIR="${APP_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"
BIN_DIR="$APP_DIR/bin"
DATA_DIR="$APP_DIR/data"
LOG_DIR="$APP_DIR/logs"
ENV_FILE="$APP_DIR/.env"
PY_LIBS="$APP_DIR/pylibs"
VERSION="${NEW_API_VERSION:-v1.0.0-rc.33}"
cd "$APP_DIR"

mkdir -p "$BIN_DIR" "$DATA_DIR" "$LOG_DIR"

if [[ ! -x "$BIN_DIR/new-api" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) artifact="new-api-${VERSION}" ;;
    aarch64|arm64) artifact="new-api-arm64-${VERSION}" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac

  url="https://github.com/QuantumNous/new-api/releases/download/${VERSION}/${artifact}"
  tmp="$BIN_DIR/.new-api.download"
  echo "Downloading ${artifact}..."
  curl --fail --location --retry 3 --retry-delay 2 --silent --show-error "$url" -o "$tmp"
  chmod 0755 "$tmp"
  mv -f "$tmp" "$BIN_DIR/new-api"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    session_secret="$(openssl rand -hex 32)"
  else
    session_secret="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  cat >"$ENV_FILE" <<EOF
PORT=3000
TZ=Asia/Shanghai
SQLITE_PATH="$DATA_DIR/new-api.db?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_txlock=immediate"
SESSION_SECRET="$session_secret"
SQL_MAX_IDLE_CONNS=4
SQL_MAX_OPEN_CONNS=20
ERROR_LOG_ENABLED=true
NODE_NAME=cloudstudio-icgsqq
EOF
  chmod 0600 "$ENV_FILE"
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# new-api 先于机器人启动:核心服务秒级就绪,不受机器人依赖安装进度影响
# (2026-09-10 平台强停后恢复时,pip install 曾拖延两个服务约 25 分钟)。
"$BIN_DIR/new-api" --log-dir "$LOG_DIR" >>"$LOG_DIR/new-api-stdout.log" 2>&1 &
echo "new-api 后台运行中(pid $!),标准输出日志: $LOG_DIR/new-api-stdout.log"

# ---- 飞书命令机器人(可选组件):文件齐全时随服务启动,崩溃自动重启 ----
# setsid 让守护循环脱离 VS Code task 进程树,IDE 会话结束时不会被连带清理。
# lark-oapi 缓存在 /workspace/pylibs:容器每次重启系统 site-packages 都会重置,
# 不缓存则每次恢复都要重新 pip install(1 核机器上可达 20 分钟以上);
# 缓存命中时跳过安装直接启动,机器人在恢复后数秒内就绪。
if [[ -f "$APP_DIR/feishu-bot.py" && -f "$APP_DIR/feishu-bot-config.json" ]] \
   && command -v python3 >/dev/null 2>&1 \
   && ! pgrep -f "feishu-bot.py" >/dev/null 2>&1; then
  echo "Starting feishu command bot..."
  if ! PYTHONPATH="$PY_LIBS" python3 -c "import lark_oapi" >/dev/null 2>&1; then
    python3 -m pip install --quiet --disable-pip-version-check \
      --target "$PY_LIBS" \
      -i https://mirrors.cloud.tencent.com/pypi/simple lark-oapi \
      || python3 -m pip install --quiet --disable-pip-version-check \
        --target "$PY_LIBS" lark-oapi \
      || echo "WARN: lark-oapi 安装失败,跳过飞书机器人" >&2
  fi
  if PYTHONPATH="$PY_LIBS" python3 -c "import lark_oapi" >/dev/null 2>&1; then
    export APP_DIR LOG_DIR PY_LIBS
    setsid bash -c 'while true; do PYTHONPATH="$PY_LIBS" python3 "$APP_DIR/feishu-bot.py" >>"$LOG_DIR/feishu-bot.log" 2>&1; echo "$(date "+%F %T") bot exited, restart in 10s" >>"$LOG_DIR/feishu-bot.log"; sleep 10; done' </dev/null >/dev/null 2>&1 &
  fi
fi

# task 前台保持一个交互 shell:
# 1. 终端里始终有 shell 读 stdin,云端浏览器可直连此终端执行运维命令
#    (Cloud Studio 的快捷键在无头浏览器里不可靠,不能依赖"新建终端");
# 2. task 主进程不退出,进程树不会被 VS Code 清理。
exec bash
