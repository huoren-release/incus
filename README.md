# Incus一键审查脚本

## 一键执行命令

```bash
curl -sLf "https://raw.githubusercontent.com/huoren-release/incus/main/incus.sh?v=$(date +%s)" | bash
```
## 定时执行

```bash
curl -sLf "https://raw.githubusercontent.com/huoren-release/incus/main/incus-cron.sh?t=$(date +%s)" | bash
```
