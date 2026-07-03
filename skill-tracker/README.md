# skill-tracker

九问Swarm 技能调用审计插件。当 Agent 调用 `skill_tool` 执行技能时，自动记录每次技能调用的审计信息，生成 JSON 文件用于分析和归档。

## 基本信息

| 项目 | 内容 |
|------|------|
| 插件名 | `skill-tracker` |
| 版本 | 1.0.0 |
| 方案 | Hook（`PreToolUse`，matcher=`skill_tool`） |
| 入口脚本 | `~/.jiuwenswarm/scripts/skill-tracker.py` |
| 源自 | 小巧灵（OpenClaw）`extensions/skill-tracker` |

## 架构

```
用户对话 → Agent LLM 推理
                │
                ▼
          Agent 决定调用 skill_tool（如 weather 技能）
                │
                ▼
UserHookRail.before_tool_call()
        │
        ├─ match("PreToolUse", "skill_tool") → 命中
        │
        └─ 启动子进程 skill-tracker.py
                │
                ├─ 解析 ARGUMENTS JSON
                ├─ 提取 skill_name（从 tool_input）
                ├─ 仅拦截 skill_tool → 非 skill_tool 直接 exit 0
                │
                ├─ 生成审计记录
                │    └─ 技能名、时间戳、session_id
                │
                ├─ 写 JSON → ~/.jiuwenswarm/skill-invocations/{ts}_{skill}.json
                ├─ 写日志 → ~/.jiuwenswarm/logs/skill-tracker.log
                │
                └─ exit 0 → 放行，Agent 正常执行技能
```

## 部署

### 1. 创建脚本

```bash
mkdir -p ~/.jiuwenswarm/scripts
```

将 `skill-tracker.py` 放入上述目录。

### 2. 修改 config.yaml

```yaml
hooks:
  disable_all_hooks: false
  PreToolUse:
    - matcher: "skill_tool"
      hooks:
        - type: command
          command: "/usr/bin/python3 ~/.jiuwenswarm/scripts/skill-tracker.py"
          timeout: 10
          shell: "bash"
```

### 3. 重启

```bash
pkill -9 -f jiuwenswarm
jiuwenswarm-start
```

### 4. 验证

对话框发送"查询天气"，然后查看：

```bash
ls ~/.jiuwenswarm/skill-invocations/
# 2026-07-02T23-47-49_weather.json

cat ~/.jiuwenswarm/logs/skill-tracker.log
# 2026-07-02 23:47:49 [INFO] [skill-tracker] skill=weather session= -> 2026-07-02T23-47-49_weather.json
```

## 输出文件

### 审计记录

路径：`~/.jiuwenswarm/skill-invocations/{时间戳}_{技能名}.json`

```json
{
  "actionPage": "九问Swarm Skill",
  "channel": "jiuwenswarm",
  "actionType": "",
  "actionModule": "JiuwenSwarm_Skill",
  "actionTitle": "Skill调用",
  "content": "{\"skill\":\"weather\",\"session_id\":\"\",\"tool_name\":\"skill_tool\",\"timestamp\":\"2026-07-02 23:47:49\"}",
  "text": "",
  "userId": "",
  "opTime": "2026-07-02 23:47:49"
}
```

### 运行日志

路径：`~/.jiuwenswarm/logs/skill-tracker.log`

```
2026-07-02 23:47:49 [INFO] [skill-tracker] skill=weather session= -> 2026-07-02T23-47-49_weather.json
2026-07-02 23:48:01 [INFO] [skill-tracker] skill=code-review session= -> 2026-07-02T23-48-01_code-review.json
2026-07-02 23:50:15 [ERROR] [skill-tracker] 写入失败: Permission denied
```

## 何时触发 vs 时不触发

| 场景 | 是否触发 |
|------|----------|
| 查询天气（调用 weather 技能） | 触发 |
| 代码审查（调用 code-review 技能） | 触发 |
| 纯文本对话（"你好"） | 不触发 |
| Agent 列出目录 / 读写文件 | 不触发（工具名不是 skill_tool） |
| Agent 调用 read 读 SKILL.md | 不触发（JiuwenSwarm 中技能通过 skill_tool 调用） |

## 方案选型

选用 **Hook 方案**而非 Extension 或 Rail：

- **Extension** 无 `PreToolUse` 事件，无法在工具调用级别拦截
- **Rail** 需要写 Python 类并 import，纯审计日志场景过度设计
- **Hook** 改 YAML 配置即生效，零侵入，完美匹配审计需求

## 配置速查

| 配置项 | 值 | 说明 |
|--------|-----|------|
| matcher | `skill_tool` | JiuwenSwarm 中技能调用的工具名 |
| command | `/usr/bin/python3 ~/.jiuwenswarm/scripts/skill-tracker.py` | 必须绝对路径 |
| shell | `bash` | Hook 执行器用 shell -c |
| timeout | `10` | 超时秒数 |
| 输出目录 | `~/.jiuwenswarm/skill-invocations/` | 审计 JSON |
| 日志目录 | `~/.jiuwenswarm/logs/` | 运行日志 |

## 踩坑记录

| 问题 | 解决 |
|------|------|
| 沙箱隔离 `/tmp/` | 所有输出路径用 `~/.jiuwenswarm/` |
| 沙箱内 Python 找不到 | 使用 `/usr/bin/python3` 绝对路径 |
| `tool_input` 是字符串不是字典 | 脚本中 `isinstance(str)` 判断后 `json.loads` |
| 工具名是 `skill_tool` 而非 `read` | JiuwenSwarm 与小巧灵的实现差异，技能读取走专用工具 |
| `session_id` 为空 | JiuwenSwarm Hook 框架暂不传递，用时间戳+技能名唯一标识 |
| Agent 纯文本回复不触发 | Hook 仅在工具调用时触发，非 LLM 文字回复 |
