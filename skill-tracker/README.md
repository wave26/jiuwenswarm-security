# security-check

JiuwenSwarm 消息安全检测插件。在用户消息进入 LLM 推理之前，调用外部安全 API 进行文本风险检测，支持 PASS / REVIEW / REJECT 三级风险判定。

## 基本信息

| 项目 | 内容 |
|------|------|
| 插件ID | `security-check` |
| 版本 | 1.0.0 |
| 方案 | Extension（`before_chat_request`） |
| 依赖 | `aiohttp >= 3.8.0` |
| 源自 | 小巧灵（OpenClaw）`extensions/security-check` |

## 架构

```
用户消息 → Gateway → ExtensionRegistry.trigger("before_chat_request")
                        │
                        ▼
               SecurityCheckExtension
                        │
            ┌───────────┼───────────┐
            ▼           ▼           ▼
         跳过检测    API 调用     API 失败
    (skipChannels/  (带重试)    (降级放行)
     accessKey未配)
            │           │
        ┌───┘     ┌─────┴─────┐
        ▼         ▼           ▼
      放行      PASS        REJECT/REVIEW
                 │         (blockReview=true)
                 ▼              │
               放行        拦截（替换消息内容）
```

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
  apiUrl: "https://your-security-api.example.com/check"
  accessKey: "your-access-key"
  appId: "default"
  tokenId: "jiuwenswarm"
  timeoutMs: 3000
  maxRetries: 2
  retryDelayMs: 500
  blockMessage: "您的消息因安全策略被拦截。"
  blockReview: false
  skipChannels: []
```

或通过环境变量：

```bash
export AI_GUARDRAIL_URL="https://your-security-api.example.com/check"
export AI_GUARDRAIL_ACCESSKEY="your-access-key"
```

### 4. 重启

```bash
pkill -9 -f jiuwenswarm
jiuwenswarm-start
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

路径：`~/.jiuwenswarm/logs/security-check.log`

格式：JSONL（每行一条 JSON）

```
{"action":"allowed","messagePreview":"你好","riskLevel":"PASS","riskDescription":"内容安全","requestId":"req-123","tokenId":"jiuwenswarm-...","attempts":1,"timestamp":"2026-07-02 15:30:00"}
{"action":"blocked","messagePreview":"危险内容...","riskLevel":"REJECT","riskDescription":"包含恶意内容","requestId":"req-456","tokenId":"jiuwenswarm-...","attempts":1,"timestamp":"2026-07-02 15:30:01"}
{"action":"skipped","messagePreview":"你好","reason":"accessKey未配置","timestamp":"2026-07-02 15:30:02"}
```

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

选用 **Extension 方案**而非 Hook 或 Rail，因为：

- **Hook** 的 `PreToolUse` 事件在工具调用时触发，此时消息已进入 Agent
- **Rail** 只有 `before_tool_call` 级事件，无法在消息进入前拦截
- **Extension** 的 `before_chat_request` 是唯一能在 LLM 推理**之前**拦截的时机

## 踩坑记录

| 问题 | 解决 |
|------|------|
| Extension 回调是否支持 async | 需确认框架版本，必要时用 `asyncio.create_task` 包装 |
| API 失败导致 Agent 卡住 | 默认降级放行，也可改为降级拦截 |
| 与 JiuwenBox 沙箱的关系 | Extension 在 AgentServer 进程内，不受沙箱网络隔离影响 |
