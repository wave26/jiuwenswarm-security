#!/usr/bin/env python3
"""confirm-tools-plus: 多维度安全检测（文件写入 + SSRF + 敏感文件读取）

部署路径：~/.jiuwenswarm/scripts/confirm-tools-plus.py
config.yaml 配置项（3 条 Hook，分别拦截不同工具）：
  hooks.PreToolUse[matcher="write|edit|create_file"].hooks[command="..."]
  hooks.PreToolUse[matcher="web_fetch|web_search"].hooks[command="..."]
  hooks.PreToolUse[matcher="read"].hooks[command="..."]
"""

import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE_DIR = Path.home() / ".jiuwenswarm"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "confirm-tools-plus.log"

DENY_SUFFIX = "禁止以任何替代方案绕过此限制！"

# ═══════════════════════════════════════════
# 1. 文件写入内容检测
# ═══════════════════════════════════════════

# WebShell 特征
WEBSHELL_PATTERNS = [
    (r'<\?php\b', 'PHP WebShell 标签'),
    (r'<\?=\s*\$', 'PHP 短标签 + 变量注入'),
    (r'<script\s+language\s*=\s*["\']php["\']', 'PHP script 标签伪装'),
    (r'<%[=\s@]*(?:eval|execute)', 'ASP/ASPX WebShell'),
    (r'<%@\s*(?:Page|Import|Assembly)\b', 'ASPX 指令伪装'),
    (r'\beval\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER|_FILES)[\[\(]', 'PHP eval + 外部变量'),
    (r'\bassert\s*\(\s*\$', 'PHP assert 后门'),
    (r'\bpreg_replace\s*\(\s*[\'"]/.*?/e[\'"]\s*,', 'PHP preg_replace /e 代码执行'),
    (r'\bcreate_function\s*\(', 'PHP create_function 代码执行'),
    (r'\bsystem\s*\(\s*\$', 'PHP system + 变量'),
    (r'\bpassthru\s*\(\s*\$', 'PHP passthru + 变量'),
    (r'\bexec\s*\(\s*\$', 'PHP exec + 变量'),
    (r'\bshell_exec\s*\(\s*\$', 'PHP shell_exec + 变量'),
    (r'\bproc_open\s*\(', 'PHP proc_open 进程执行'),
    (r'\bpopen\s*\(', 'PHP popen 管道执行'),
    (r'\`\s*\$', 'PHP 反引号命令执行'),
    (r'JNDI\s*:inject', 'JNDI 注入利用'),
]

# 后门 / 恶意代码
BACKDOOR_PATTERNS = [
    (r'\bos\.system\s*\(', 'Python os.system 调用'),
    (r'\bsubprocess\.(?:call|Popen|check_output|run)\s*\(', 'Python subprocess 调用'),
    (r"__import__\s*\(\s*['\"]os['\"]\s*\)", 'Python 动态导入 os'),
    (r'\bsocket\.socket\s*\(', 'Python socket 后门'),
    (r'child_process\.exec\s*\(', 'Node.js 子进程执行'),
    (r'require\s*\(\s*[\'"]child_process[\'"]\s*\)', 'Node.js child_process 引入'),
    (r'\bRuntime\.getRuntime\(\)\.exec\s*\(', 'Java Runtime.exec'),
    (r'\bProcessBuilder\s*\(', 'Java ProcessBuilder'),
    (r'new\s+Function\s*\(', 'JavaScript 动态函数构造'),
]

# SSH authorized_keys 注入
SSH_INJECT_PATTERNS = [
    (r'ssh-(?:rsa|ed25519|dss|ecdsa)\s+AAAA', 'SSH 公钥注入'),
]

# Shell 配置文件劫持
SHELL_RC_PATTERNS = [
    (r'^\s*alias\s+(?:ls|sudo|su|vi|cat|mv|cp|rm|ps|who)\s*=', 'Shell alias 劫持'),
    (r'^\s*\*\s+\*\s+\*\s+\*\s+\*\s+.*\|\s*(?:sh|bash|nc)', 'Crontab 后门'),
    (r'^\s*@(?:reboot|hourly|daily)\s+.*(?:sh|bash|nc|curl)', 'Crontab @reboot 后门'),
]

SENSITIVE_WRITE_PATHS = [
    (r'(?:^|/)(?:authorized_keys|id_rsa\b|id_ed25519\b|id_dsa\b)', 'SSH 密钥文件'),
    (r'(?:^|/)\.bashrc$', 'Bash 配置文件'),
    (r'(?:^|/)\.zshrc$', 'Zsh 配置文件'),
    (r'(?:^|/)\.profile$', 'Shell 配置文件'),
    (r'(?:^|/)crontab$', 'Crontab 文件'),
    (r'(?:^|/)\.(?:env|secret|credentials)\b', '凭据文件'),
    (r'(?:^|/)(?:Makefile|CMakeLists\.txt)\b', '构建文件（供应链攻击）'),
    (r'(?:^|/)(?:package\.json|setup\.py|Cargo\.toml|go\.mod)\b', '包管理器文件'),
]

# ═══════════════════════════════════════════
# 2. SSRF / 数据外传防护
# ═══════════════════════════════════════════

SSRF_PATTERNS = [
    (r'^https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}', '内网 A 类地址 (10.x)'),
    (r'^https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', '内网 B 类地址 (172.16-31.x)'),
    (r'^https?://192\.168\.\d{1,3}\.\d{1,3}', '内网 C 类地址 (192.168.x)'),
    (r'^https?://127\.\d{1,3}\.\d{1,3}\.\d{1,3}', '本地回环地址'),
    (r'^https?://localhost\b', 'localhost 访问'),
    (r'^https?://\[::1\]', 'IPv6 回环地址'),
    (r'^https?://0\.0\.0\.0', '全零地址'),
    (r'^https?://169\.254\.169\.254', '云元数据服务 (AWS/GCP/Azure)'),
    (r'^https?://metadata\.google\.internal', 'GCP 元数据服务'),
    (r'^https?://[^/]*\.compute\.internal\b', 'GCP 内部服务'),
    (r'^https?://100\.\d{1,3}\.\d{1,3}\.\d{1,3}', '运营商 NAT 地址 (100.x)'),
]

EXFILTRATION_PATTERNS = [
    (r'\bcurl\b.*\s+-[dD]\s+', 'curl POST 数据外传'),
    (r'\bwget\b.*\s+--post-data\b', 'wget POST 数据外传'),
]

# ═══════════════════════════════════════════
# 3. 敏感文件读取检测
# ═══════════════════════════════════════════

SENSITIVE_READ_PATHS = [
    # 凭据/密钥
    (r'(?:^|/)\.env\b', '环境变量凭据文件'),
    (r'(?:^|/)\.secret\b', '密钥文件'),
    (r'(?:^|/)credentials\.(?:json|yml|yaml|ini|conf)\b', '凭据文件'),
    (r'(?:^|/)password', '密码相关文件'),
    (r'(?:^|/)secret\b.*\.(?:json|yml|yaml|ini|conf|txt)$', '密钥文件'),
    (r'(?:^|/)token\b', '令牌文件'),
    (r'(?:^|/)api[_-]?key', 'API 密钥'),
    (r'(?:^|/)\.(?:pem|key|crt|cer|p12|pfx)\b', '证书/私钥文件'),
    # SSH
    (r'(?:^|/)(?:id_rsa|id_ed25519|id_dsa|id_ecdsa)(?:\.pub)?$', 'SSH 私钥'),
    (r'(?:^|/)authorized_keys$', 'SSH 授权密钥'),
    (r'(?:^|/)known_hosts$', 'SSH 已知主机'),
    (r'(?:^|/)\.ssh/config$', 'SSH 配置'),
    # 云凭据
    (r'(?:^|/)\.aws/credentials\b', 'AWS 凭据'),
    (r'(?:^|/)\.aws/config\b', 'AWS 配置'),
    (r'(?:^|/)(?:\.gcp|gcloud)/', 'GCP 凭据'),
    (r'(?:^|/)\.azure/', 'Azure 凭据'),
    (r'(?:^|/)\.kube/config\b', 'Kubernetes 配置'),
    # 系统敏感
    (r'(?:^|/)/etc/shadow\b', '系统密码哈希'),
    (r'(?:^|/)/etc/passwd\b', '系统用户信息'),
    (r'(?:^|/)\.(?:bash_history|zsh_history|mysql_history|psql_history|python_history)\b', '命令历史'),
    # 配置
    (r'(?:^|/)config\.(?:json|yml|yaml|ini|conf|toml)\b', '通用配置文件'),
    (r'(?:^|/)application\.(?:properties|yml|yaml)\b', '应用配置文件'),
    (r'(?:^|/)settings\.(?:py|ini|conf)\b', '设置文件'),
    (r'(?:^|/)Dockerfile\b', 'Docker 构建文件'),
    (r'(?:^|/)docker-compose\.(?:yml|yaml)\b', 'Docker Compose 文件'),
    (r'(?:^|/)\.docker/config\.json\b', 'Docker Hub 凭据'),
]


def now_str():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def write_log(level, msg):
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{now_str()} [{level}] [confirm-tools-plus] {msg}\n")
    except Exception:
        pass


# ── Handler: 文件写入内容检测 ──

def check_write(tool_name, tool_input):
    path = tool_input.get("path", "") or tool_input.get("file_path", "") or tool_input.get("name", "")
    if not path:
        write_log("INFO", "跳过: 无文件路径")
        return

    # 收集要检测的内容
    contents = []
    if "content" in tool_input:
        contents.append(tool_input["content"])
    if "edits" in tool_input and isinstance(tool_input["edits"], list):
        for edit in tool_input["edits"]:
            if "newText" in edit:
                contents.append(edit["newText"])
            elif "content" in edit:
                contents.append(edit["content"])

    combined = "\n".join(contents)
    if not combined:
        write_log("INFO", "跳过: 无写入内容")
        return

    # 针对文件路径的敏感路径检测
    for pattern, desc in SENSITIVE_WRITE_PATHS:
        if re.search(pattern, path, re.I):
            msg = f"[DENY] 写入敏感路径被拦截 — {desc}: {path}。{DENY_SUFFIX}"
            write_log("WARN", f"拒绝写入敏感路径: path={path} desc={desc}")
            print(msg, file=sys.stderr)
            sys.exit(2)

    # SSH 注入 + 路径为 authorized_keys
    if re.search(r'(?:^|/)authorized_keys$', path, re.I):
        for pattern, desc in SSH_INJECT_PATTERNS:
            if re.search(pattern, combined, re.I):
                msg = f"[DENY] SSH 公钥注入被拦截 — {desc}。{DENY_SUFFIX}"
                write_log("WARN", f"拒绝SSH注入: {desc[:50]}")
                print(msg, file=sys.stderr)
                sys.exit(2)

    # Shell 配置文件劫持
    if re.search(r'(?:^|/)\.(?:bashrc|zshrc|profile)$', path, re.I):
        for pattern, desc in SHELL_RC_PATTERNS:
            if re.search(pattern, combined, re.M | re.I):
                msg = f"[DENY] Shell 配置劫持被拦截 — {desc}。{DENY_SUFFIX}"
                write_log("WARN", f"拒绝Shell劫持: {desc[:50]}")
                print(msg, file=sys.stderr)
                sys.exit(2)

    # 通用内容检测 (WebShell + 后门)
    all_patterns = WEBSHELL_PATTERNS + BACKDOOR_PATTERNS
    for pattern, desc in all_patterns:
        if re.search(pattern, combined, re.I):
            msg = f"[DENY] 写入文件含恶意代码 — {desc}。{DENY_SUFFIX}"
            write_log("WARN", f"拒绝恶意写入: {desc[:50]} in {path}")
            print(msg, file=sys.stderr)
            sys.exit(2)

    write_log("INFO", f"写入检测通过: path={path}")


# ── Handler: SSRF / 数据外传 ──

def check_fetch(tool_name, tool_input):
    url = ""
    if "url" in tool_input:
        url = tool_input["url"]
    elif "urls" in tool_input and isinstance(tool_input["urls"], list):
        url = tool_input["urls"][0]
    elif "query" in tool_input:
        # 搜索查询 — 提取 URL
        query = tool_input["query"]
        urls = re.findall(r'https?://[^\s]+', query)
        if not urls:
            write_log("INFO", "跳过: 搜索查询无URL")
            return
        url = urls[0]

    if not url:
        write_log("INFO", "跳过: 无URL")
        return

    write_log("INFO", f"检测 URL: {url[:100]}")

    for pattern, desc in SSRF_PATTERNS:
        if re.search(pattern, url, re.I):
            msg = f"[DENY] SSRF 访问被拦截 — {desc}: {url[:80]}。{DENY_SUFFIX}"
            write_log("WARN", f"拒绝SSRF: {desc} url={url[:100]}")
            print(msg, file=sys.stderr)
            sys.exit(2)

    # 外传检测（curl -d / wget --post-data）
    if "command" in tool_input:
        cmd = tool_input["command"]
        for pattern, desc in EXFILTRATION_PATTERNS:
            if re.search(pattern, cmd, re.I):
                msg = f"[DENY] 数据外传被拦截 — {desc}。{DENY_SUFFIX}"
                write_log("WARN", f"拒绝外传: {desc}")
                print(msg, file=sys.stderr)
                sys.exit(2)

    write_log("INFO", f"URL检测通过: {url[:80]}")


# ── Handler: 敏感文件读取 ──

def check_read(tool_name, tool_input):
    path = tool_input.get("path", "") or tool_input.get("file_path", "") or tool_input.get("name", "")
    if not path:
        write_log("INFO", "跳过: 无文件路径")
        return

    for pattern, desc in SENSITIVE_READ_PATHS:
        if re.search(pattern, path, re.I):
            msg = f"[DENY] 读取敏感文件被拦截 — {desc}: {path}。{DENY_SUFFIX}"
            write_log("WARN", f"拒绝读取: path={path} desc={desc}")
            print(msg, file=sys.stderr)
            sys.exit(2)

    write_log("INFO", f"读取检测通过: path={path}")


# ── 路由分发 ──

def main():
    raw = os.environ.get("ARGUMENTS", "")
    if not raw:
        raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}

    tool_name = hook_input.get("tool_name", "")
    tool_input_raw = hook_input.get("tool_input", {})

    if isinstance(tool_input_raw, str):
        try:
            tool_input = json.loads(tool_input_raw)
        except json.JSONDecodeError:
            tool_input = {}
    elif isinstance(tool_input_raw, dict):
        tool_input = tool_input_raw
    else:
        sys.exit(0)

    # 路由
    if tool_name in ("write", "edit", "create_file"):
        check_write(tool_name, tool_input)
    elif tool_name in ("web_fetch", "web_search"):
        check_fetch(tool_name, tool_input)
    elif tool_name in ("read",):
        check_read(tool_name, tool_input)
    else:
        write_log("INFO", f"未识别的工具: {tool_name}")

    sys.exit(0)


if __name__ == "__main__":
    main()
