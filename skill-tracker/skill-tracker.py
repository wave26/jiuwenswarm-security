#!/usr/bin/env python3
"""skill-tracker: 记录每次技能调用（skill_tool）的审计日志。

部署路径：~/.jiuwenswarm/scripts/skill-tracker.py
config.yaml 配置项：
  hooks.PreToolUse[matcher="skill_tool"].hooks[command="/usr/bin/python3 ~/.jiuwenswarm/scripts/skill-tracker.py"]
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE_DIR = Path.home() / ".jiuwenswarm"
OUTPUT_DIR = BASE_DIR / "skill-invocations"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "skill-tracker.log"


def now_utc8():
    return datetime.now(timezone(timedelta(hours=8)))


def format_time(d):
    return d.strftime("%Y-%m-%d %H:%M:%S")


def log(level, msg):
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{format_time(now_utc8())} [{level}] [skill-tracker] {msg}\n")
    except Exception:
        pass


def main():
    # 优先从环境变量读取，回退到 stdin
    raw = os.environ.get("ARGUMENTS", "")
    if not raw:
        raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}

    tool_name = hook_input.get("tool_name", "")
    tool_input_raw = hook_input.get("tool_input", {})
    session_id = hook_input.get("session_id", "")

    # 仅拦截 skill_tool
    if tool_name != "skill_tool":
        sys.exit(0)

    # tool_input 可能是字符串（JSON）或字典
    if isinstance(tool_input_raw, str):
        try:
            tool_input = json.loads(tool_input_raw)
        except json.JSONDecodeError:
            tool_input = {}
    elif isinstance(tool_input_raw, dict):
        tool_input = tool_input_raw
    else:
        sys.exit(0)

    skill_name = tool_input.get("skill_name", "")
    if not skill_name:
        sys.exit(0)

    now = format_time(now_utc8())

    record = {
        "actionPage": "JiuwenSwarm Skill",
        "channel": "jiuwenswarm",
        "actionType": "",
        "actionModule": "JiuwenSwarm_Skill",
        "actionTitle": "Skill调用",
        "content": json.dumps({
            "skill": skill_name,
            "session_id": session_id,
            "tool_name": tool_name,
            "timestamp": now,
        }, ensure_ascii=False),
        "text": "",
        "userId": "",
        "opTime": now,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = now.replace(" ", "T").replace(":", "-").replace(".", "-")[:19]
    output_file = OUTPUT_DIR / f"{ts}_{skill_name}.json"

    try:
        output_file.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        log("INFO", f"skill={skill_name} session={session_id} -> {output_file.name}")
    except Exception as e:
        log("ERROR", f"写入失败: {e}")

    sys.exit(0)


if __name__ == "__main__":
    main()
