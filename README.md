# cloudstudio-ops

腾讯 Cloud Studio 免费空间(eitan/icgsqq)的**自动部署通道**。

容器内的飞书命令机器人每分钟轮询本仓库的 `manifest.json`,发现版本号变化时
自动下载文件列表中的内容,经 sha256 与语法校验后应用到 `/workspace/`。

- 仓库内容仅限部署脚本,**不含任何密钥**(机器人凭证在容器本地的
  feishu-bot-config.json 中,已排除在仓库之外)
- 文件先落 `.new` 再原子替换,校验失败保持原文件不动
- `manifest.json` 的 `restart: "bot"` 表示应用后由守护进程自动重启机器人

| 文件 | 用途 |
|---|---|
| `feishu-bot.py` | 飞书命令机器人(命令执行、状态卡片、自动部署轮询) |
| `run-new-api.sh` | new-api 与机器人的启动脚本(preview.yml 调用) |
| `manifest.json` | 部署清单:版本号 + 文件哈希 |
