# security-check

JiuwenSwarm 消息安全检测插件。在用户消息进入 LLM 推理之前，调用外部安全 API 进行文本风险检测，支持 PASS / REVIEW / REJECT 三级风险判定。

## 基本信息

| 项目 | 内容 |
|------|------|
| 插件ID | `security-check` |
| 版本 | 1.0.1 |
| 方案 | Extension（`gateway:before_chat_request` + `agent_server:before_chat_request`） |
| 依赖 | 无（使用标准库 urllib） |
| 源自 | OpenClaw `extensions/security-check` |

## 架构：双阶段接力

```
用户消息 "rm -rf"
    │
    ▼
┌─ Gateway ────────────────────────────────────────┐
│ ① gateway:before_chat_request                    │
│   → API 检测 → REJECT                            │
│   → 替换 content + query = "拦截提示"             │
│   → 放行（消息已替换）                             │
└─────────────────────┬────────────────────────────┘
                      │ 消息内容已是 "拦截提示"
                      ▼
┌─ AgentServer ────────────────────────────────────┐
│ ② agent_server:before_chat_request               │
│   → API 检测 "拦截提示" → PASS                    │
│   → 放行给 LLM                                   │
└─────────────────────┬────────────────────────────┘
                      ▼
                   Agent LLM
              "我收到了您的消息。似乎触发了安全策略..."
```

**双注册原因**：GatewayHookEvents 只覆盖 API/外部调用路径，Web UI 直连走 AgentServerHookEvents。两者是不同的 hook 事件，必须分别注册。

## 部署

### 1. 创建目录

```bash
mkdir -p ~/.jiuwenswarm/extensions/security-check
```

### 2. 放置文件

将以下文件放入上述目录：
- `extension.yaml` — 扩展清单
- `extension.py` — 扩展入口
- `README.md` — 本文件

### 3. 配置

在 `~/.jiuwenswarm/config/config.yaml` 中：

```yaml
extensions:
  extension_dirs: "jiuwenswarm/extensions;~/.jiuwenswarm/extensions"

security-check:
  apiUrl: "http://localhost:3456/api/v1/guardrail/check"
  accessKey: "mock-access-key-for-testing"
  appId: "default"
  tokenId: "jiuwenswarm"
  timeoutMs: 3000
  maxRetries: 2
  retryDelayMs: 500
  blockMessage: "您的消息因安全策略被拦截。"
  blockReview: false
  skipChannels: []
```

本地测试时可启动 mock 服务器：

```bash
python mock-server.py
```

或通过环境变量：

```bash
export AI_GUARDRAIL_URL="http://localhost:3456/api/v1/guardrail/check"
export AI_GUARDRAIL_ACCESSKEY="mock-access-key-for-testing"
```

### 4. 重启

```bash
pkill -9 -f jiuwenswarm
jiuwenswarm-start
```

### 5. 验证

```bash
# 查看加载日志
grep -i "security-check" ~/.jiuwenswarm/agent/.logs/gateway.log | tail -5

# 应看到: [security-check] 已注册 handler（Gateway + AgentServer）

# 在 Web UI 输入危险命令（如 rm -rf），观察审计日志
cat ~/.jiuwenswarm/logs/security-check.log
# 应看到成对记录：一条 blocked + 一条 allowed
```

## 安全 API 接口

### 请求

```json
{
  "eventId": "input",
  "data": {
    "tokenId": "jiuwenswarm-<timestamp>-<session>",
    "text": "用户消息内容"
  },
  "accessKey": "your-access-key",
  "appId": "default",
  "type": "TEXTRISK"
}
```

### 响应

```json
{
  "riskLevel": "PASS",
  "riskDescription": "内容安全",
  "requestId": "req-xxxxxxxx"
}
```

### 风险等级

| 等级 | 行为 |
|------|------|
| `PASS` | 放行 |
| `REVIEW` | 根据 `blockReview` 配置决定 |
| `REJECT` | 直接拦截 |

## 审计日志

路径：`~/.jiuwenswarm/logs/security-check.log`，格式：JSONL（每行一条 JSON）

```
{"action":"blocked","messagePreview":"rm -rf","riskLevel":"REJECT","riskDescription":"危险命令","requestId":"mock-xxx","attempts":1,"tokenId":"sess_xxx","timestamp":"2026-07-03 14:07:50"}
{"action":"allowed","messagePreview":"您的消息因安全策略被拦截。","riskLevel":"PASS","riskDescription":"","requestId":"mock-yyy","attempts":1,"tokenId":"sess_yyy","timestamp":"2026-07-03 14:07:50"}
```

> **注意**：每次消息产生两条审计记录（一条 blocked + 一条 allowed）是正常行为，对应 Gateway → AgentServer 双阶段接力，不是重复检测。

| 动作 | 含义 |
|------|------|
| `allowed` | 通过安全检测 |
| `blocked` | 被拦截 |
| `skipped` | 跳过检测（未配置/Channel 跳过/API 失败） |

## 配置项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `apiUrl` | — | 安全 API 地址（必须） |
| `accessKey` | — | API 密钥（未配置则跳过检测） |
| `appId` | `"default"` | 应用 ID |
| `tokenId` | `"jiuwenswarm"` | 默认 Token ID |
| `timeoutMs` | `3000` | 单次请求超时（毫秒） |
| `maxRetries` | `2` | 最大重试次数 |
| `retryDelayMs` | `500` | 重试间隔（毫秒） |
| `blockMessage` | `"您的消息因安全策略被拦截。"` | 拦截提示 |
| `blockReview` | `false` | REVIEW 级别是否拦截 |
| `skipChannels` | `[]` | 跳过检测的 Channel ID 列表 |

## 方案选型

选用 **Extension 方案**而非 Hook 或 Rail：

| 方案 | 触发时机 | 适用性 |
|------|---------|--------|
| **Extension**（选用） | `before_chat_request` — 消息进入 LLM **之前** | 消息级安全检测唯一可行方案 |
| Hook | `PreToolUse` — 工具调用时 | 此时消息已进入 Agent，太迟 |
| Rail | `before_tool_call` — 工具调用前 | 无法在消息进入前拦截 |

## 踩坑记录

| # | 问题 | 解决 |
|---|------|------|
| 1 | `register("before_chat_request", ...)` 不触发 | 事件名必须用 `GatewayHookEvents.BEFORE_CHAT_REQUEST`（实际值 `"gateway:before_chat_request"`），`HookEventBase.get_event()` 会加 scope 前缀 |
| 2 | Web UI 输入危险命令 Agent 仍能收到 | 只注册了 Gateway 事件，遗漏 AgentServer 路径。需同时注册 `AgentServerHookEvents.BEFORE_CHAT_REQUEST` |
| 3 | 拦截后 Agent 仍看到原始 `rm -rf` | 只改了 `params["content"]`，但 Agent 从 `params["query"]` 读取消息，两者都需替换 |
| 4 | `ExtensionConfig.__init__() missing required argument 'logger'` | `ExtensionConfig(config=sc)` 缺 `logger`，改为 `ExtensionConfig(config=sc, logger=logger)` |
| 5 | `Can't instantiate abstract class` | `BaseExtension` 是抽象类，必须实现 `initialize()` 和 `shutdown()` |
| 6 | 前端消息气泡仍显示 `rm -rf` | 服务端原地替换 params 不会反向通知前端。纯视觉效果，不影响安全。可选优化：Gateway 通过 WebSocket 推送 `chat.censor` 事件 |

## 可选优化

当前前端消息气泡不自动刷新（hook 只在服务端替换，不反向通知 UI）。如需前端同步，涉及 3 处小改（约 13 行）：

1. **extension.py**：拦截后设标记 → `params["__censored__"] = True`
2. **message_handler.py**：检查标记，WebSocket 推送 `chat.censor` 事件
3. **chatStore.ts**：监听事件，更新消息气泡文本
