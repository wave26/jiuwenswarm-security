"""security-check Extension: 用户消息安全检测。

部署路径：~/.jiuwenswarm/extensions/security-check/
  extension.yaml  extension.py

config.yaml 配置项：
  extensions.extension_dirs: 需包含 ~/.jiuwenswarm/extensions（或绝对路径）
  security-check.*: 扩展自身配置
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

from jiuwenswarm.extensions.sdk import BaseExtension
from jiuwenswarm.extensions.types import ExtensionConfig
from jiuwenswarm.extensions.hook_event import GatewayHookEvents, AgentServerHookEvents

logger = logging.getLogger(__name__)

LOG_DIR = Path.home() / ".jiuwenswarm" / "logs"
LOG_FILE = LOG_DIR / "security-check.log"
MAX_MSG_PREVIEW = 50


def now_str():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def write_audit(entry: dict):
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        entry["timestamp"] = now_str()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning(f"写入审计日志失败: {e}")


class SecurityCheckExtension(BaseExtension):
    """安全检测扩展：调用外部 API 检测用户消息风险。"""

    config: dict
    skip_channels: set

    async def initialize(self, config: ExtensionConfig) -> None:
        cfg = config.config if hasattr(config, 'config') else {}
        self.config = {
            "apiUrl": cfg.get("apiUrl") or os.environ.get("AI_GUARDRAIL_URL", ""),
            "accessKey": cfg.get("accessKey") or os.environ.get("AI_GUARDRAIL_ACCESSKEY", ""),
            "appId": cfg.get("appId", "default"),
            "tokenId": cfg.get("tokenId", "jiuwenswarm"),
            "timeoutMs": cfg.get("timeoutMs", 3000),
            "maxRetries": cfg.get("maxRetries", 2),
            "retryDelayMs": cfg.get("retryDelayMs", 500),
            "blockMessage": cfg.get("blockMessage", "您的消息因安全策略被拦截。"),
            "blockReview": cfg.get("blockReview", False),
        }
        self.skip_channels = set(cfg.get("skipChannels", []))

        if not self.config["accessKey"]:
            logger.warning("[security-check] accessKey 未配置，跳过检测")
        logger.warning("[security-check] 初始化完成 apiUrl=%s accessKey=%s",
                       self.config["apiUrl"], "SET" if self.config["accessKey"] else "EMPTY")

    async def shutdown(self) -> None:
        logger.info("[security-check] 关闭")

    def _call_api(self, text: str, token_id: str) -> dict | None:
        """同步调用安全检测 API，返回 riskLevel / riskDescription / requestId 或 None。"""
        body = json.dumps({
            "eventId": "input",
            "data": {"tokenId": token_id, "text": text},
            "accessKey": self.config["accessKey"],
            "appId": self.config["appId"],
            "type": "TEXTRISK",
        }).encode()

        timeout_sec = self.config["timeoutMs"] / 1000
        req = urllib.request.Request(
            self.config["apiUrl"], data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                data = json.loads(resp.read())
            if "riskLevel" not in data:
                return None
            return {
                "riskLevel": data["riskLevel"],
                "riskDescription": data.get("riskDescription", ""),
                "requestId": data.get("requestId", ""),
            }
        except Exception as e:
            logger.warning(f"[security-check] API 调用失败: {e}")
            return None

    async def handle_before_chat(self, context) -> None:
        """异步回调：在消息进入 LLM 前检测并拦截。

        context 是 GatewayChatHookContext dataclass 对象（非 dict），
        字段: request_id, channel_id, session_id, params(dict)
        修改 context.params["content"] 可原地改变用户消息（params 与 Message.params 同引用）。

        必须为 async：AsyncCallbackFramework.trigger 会 await callback 返回值，
        同步函数返回 None 会导致 await None 抛 TypeError。
        """
        try:
            await self._do_handle(context)
        except Exception:
            import traceback
            logger.error("[security-check] 异常:\n%s", traceback.format_exc())

    async def _do_handle(self, context) -> None:
        # 1. 提取消息体（dataclass 属性访问，兼容 dict 以防万一）
        if isinstance(context, dict):
            params = context.get("params", {})
            channel_id = params.get("channel_id", "")
            session_key = params.get("session_id", "")
        else:
            params = getattr(context, "params", {})
            channel_id = getattr(context, "channel_id", "")
            session_key = getattr(context, "session_id", "")

        msg = params.get("content", "") or params.get("query", "") or params.get("body", "")
        if not msg or not msg.strip():
            return

        # 消息预览
        msg_safe = re.sub(r"[^\u4e00-\u9fff\u3000-\u303f\uff00-\uffefa-zA-Z0-9 +-]",
                          " ", msg)
        msg_parts = [w for w in msg_safe.split(" ") if w]
        msg_preview = " ".join(msg_parts[:20])

        # 2. 跳过检测的条件
        if channel_id and channel_id in self.skip_channels:
            write_audit({"action": "skipped", "channelId": channel_id,
                         "messagePreview": msg_preview, "reason": "channel跳过"})
            return

        if not self.config.get("accessKey"):
            write_audit({"action": "skipped", "messagePreview": msg_preview,
                         "reason": "accessKey未配置"})
            return

        # 3. 调用 API（带重试）
        token_id = f"{session_key or self.config['tokenId']}-{int(datetime.now().timestamp() * 1000)}"
        logger.info("[security-check] 检测: tokenId=%s", token_id)

        result = None
        max_attempts = self.config["maxRetries"] + 1
        for attempt in range(1, max_attempts + 1):
            result = await asyncio.to_thread(self._call_api, msg, token_id)
            if result:
                result["attempts"] = attempt
                break
            if attempt < max_attempts and self.config["retryDelayMs"] > 0:
                await asyncio.sleep(self.config["retryDelayMs"] / 1000)

        # 4. API 失败降级放行
        if not result:
            logger.warning("[security-check] 检测失败，降级放行")
            write_audit({"action": "skipped", "messagePreview": msg_preview,
                         "reason": "API错误"})
            return

        # 5. REJECT 拦截
        if result["riskLevel"] == "REJECT":
            logger.warning("[security-check] 拦截(REJECT): %s requestId=%s",
                           result.get("riskDescription", ""), result.get("requestId", ""))
            write_audit({"action": "blocked", "messagePreview": msg_preview,
                         "riskLevel": "REJECT", **result, "tokenId": token_id})
            # Agent 从 params["query"] 读用户消息（非 params["content"]），两者都需替换
            params["content"] = self.config["blockMessage"]
            params["query"] = self.config["blockMessage"]
            return

        # 6. REVIEW 拦截（需 blockReview 配置开启）
        if result["riskLevel"] == "REVIEW" and self.config.get("blockReview"):
            logger.info("[security-check] 拦截(REVIEW): %s", result.get("riskDescription", ""))
            write_audit({"action": "blocked", "messagePreview": msg_preview,
                         "riskLevel": "REVIEW", **result, "tokenId": token_id,
                         "reason": "REVIEW拦截"})
            params["content"] = self.config["blockMessage"]
            params["query"] = self.config["blockMessage"]
            return

        # 7. PASS 放行
        write_audit({"action": "allowed", "messagePreview": msg_preview,
                     **result, "tokenId": token_id})


async def register_extensions(registry):
    """Extension 入口函数，框架自动调用。"""
    import yaml

    ext = SecurityCheckExtension()

    # 手动初始化（ExtensionManager 不调 initialize，需自行读取配置）
    cfg_path = os.path.expanduser("~/.jiuwenswarm/config/config.yaml")
    if os.path.exists(cfg_path):
        with open(cfg_path, encoding="utf-8") as f:
            full = yaml.safe_load(f) or {}
        sc = full.get("security-check", {})
        await ext.initialize(ExtensionConfig(config=sc, logger=logger))

    # ★ 关键：事件名必须用 HookEvents 常量（如 "gateway:before_chat_request"），
    #   不能用裸字符串 "before_chat_request"，因为 HookEventBase.get_event() 会加 scope 前缀。
    #   同时注册 Gateway 和 AgentServer 两个事件：
    #   - Gateway         覆盖 API/外部调用路径
    #   - AgentServer     覆盖 Web UI 直连路径
    registry.register(GatewayHookEvents.BEFORE_CHAT_REQUEST, ext.handle_before_chat)
    registry.register(AgentServerHookEvents.BEFORE_CHAT_REQUEST, ext.handle_before_chat)
    logger.warning("[security-check] 已注册 handler（Gateway + AgentServer）")
    return [ext]
