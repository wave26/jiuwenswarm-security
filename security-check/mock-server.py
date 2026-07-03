# Mock 安全检测服务 — 用于 security-check 插件本地测试
# 启动: python mock-server.py
# 默认监听 http://localhost:3456
#
# 测试验证:
#   拦截: curl -X POST http://localhost:3456 -H "Content-Type: application/json" -d "{\"eventId\":\"input\",\"data\":{\"tokenId\":\"t1\",\"text\":\"rm -rf\"},\"accessKey\":\"k\",\"appId\":\"d\",\"type\":\"TEXTRISK\"}"
#   放行: curl -X POST http://localhost:3456 -H "Content-Type: application/json" -d "{\"eventId\":\"input\",\"data\":{\"tokenId\":\"t1\",\"text\":\"hello world\"},\"accessKey\":\"k\",\"appId\":\"d\",\"type\":\"TEXTRISK\"}"

import json
import random
import string
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 3456

# ====== 检测规则 ======
RULES = [
    # REJECT: 命中直接拦截
    {"riskLevel": "REJECT", "keywords": ["rm -rf", "shutdown", "reboot", "mkfs", "format"], "reason": "危险命令实例"},
    {"riskLevel": "REJECT", "keywords": ["sql注入", "xss", "漏洞", "木马", "病毒", "钓鱼"], "reason": "攻击/威胁关键词"},
    {"riskLevel": "REJECT", "keywords": ["自杀", "self-harm", "kill myself"], "reason": "自伤风险内容"},

    # REVIEW: 命中标记为需审核
    {"riskLevel": "REVIEW", "keywords": ["密码", "password", "秘密", "secret", "密钥"], "reason": "敏感词—凭证/机密"},
    {"riskLevel": "REVIEW", "keywords": [" porn ", "色情", "赌博", "武器"], "reason": "敏感词—违规内容"},
]


def gen_request_id():
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"mock-{int(time.time() * 1000)}-{suffix}"


class MockGuardHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 读取请求体
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        # 验证请求格式
        if data.get("type") != "TEXTRISK" or not data.get("data", {}).get("text"):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid request format, expect type=TEXTRISK + data.text"}).encode())
            return

        text = data["data"]["text"]
        token_id = data["data"].get("tokenId", "unknown")
        print(f"[{self.log_date_time_string()}] tokenId={token_id} text=\"{text[:80]}\"")

        # 按优先级匹配规则
        for rule in RULES:
            matched = any(kw.lower() in text.lower() for kw in rule["keywords"])
            if matched:
                result = {
                    "riskLevel": rule["riskLevel"],
                    "riskDescription": f"{rule['reason']}: \"{text[:60]}\"",
                    "requestId": gen_request_id(),
                }
                print(f"  → {rule['riskLevel']}: {rule['reason']}")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result, ensure_ascii=False).encode())
                return

        # PASS
        result = {
            "riskLevel": "PASS",
            "riskDescription": "",
            "requestId": gen_request_id(),
        }
        print("  → PASS")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result, ensure_ascii=False).encode())

    def log_message(self, format, *args):
        pass  # 禁用默认日志，用 print 代替


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), MockGuardHandler)
    print("=" * 48)
    print("  Mock 安全检测服务已启动")
    print(f"  地址: http://localhost:{PORT}")
    print("=" * 48)
    print("")
    print("测试验证:")
    print(f"  拦截: curl -X POST http://localhost:{PORT} -H \"Content-Type: application/json\" -d '{{\"eventId\":\"input\",\"data\":{{\"tokenId\":\"t1\",\"text\":\"rm -rf\"}},\"accessKey\":\"k\",\"appId\":\"d\",\"type\":\"TEXTRISK\"}}'")
    print(f"  放行: curl -X POST http://localhost:{PORT} -H \"Content-Type: application/json\" -d '{{\"eventId\":\"input\",\"data\":{{\"tokenId\":\"t1\",\"text\":\"hello world\"}},\"accessKey\":\"k\",\"appId\":\"d\",\"type\":\"TEXTRISK\"}}'")
    print("")
    print("配置环境变量后启动 JiuwenSwarm:")
    print(f"  export AI_GUARDRAIL_URL='http://localhost:{PORT}'")
    print("  export AI_GUARDRAIL_ACCESSKEY='test-key'")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMock 安全检测服务已停止")
