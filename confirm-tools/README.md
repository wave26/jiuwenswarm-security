## 推荐方案：规则迁移（减少冗余，提升性能）

### 对比分析

confirm-tools 共 27 条黑名单 + 6 条混淆 + 内联检测。而 JiuwenSwarm v0.2.2 内置的 `builtin_rules.yaml` 已有 10 条 Shell 高危规则，运行在 `tiered_policy` 引擎内（进程内高效正则匹配，无子进程开销）。

**覆盖率对比：**

| 对比维度 | confirm-tools (Hook) | builtin_rules.yaml (内置) |
|---|---|---|
| 覆盖规则数 | 33+ | 10 |
| 重叠覆盖 | — | 80%（26/33） |
| **未覆盖（高价值）** | **7 条** | 0 |
| 执行方式 | 子进程 spawn Python | 进程内正则匹配 |
| 性能开销 | 每次 bash ~200ms | <1ms |
| 配置复杂度 | Hook 配置 + 脚本 | YAML 规则 |
| 与其他权限体系集成 | 独立运行 | tiered_policy 统一决策 |

### 未覆盖的 7 条规则

| # | 规则 | 风险等级 | 说明 |
|---|---|---|---|
| 1 | `chmod 777` / `666` / `000` | CRITICAL | 授予过于宽松/严格权限 |
| 2 | `chown root` / `system` | CRITICAL | 文件所有权变更到特权用户 |
| 3 | `truncate -s 0` / `cat /dev/null >` | HIGH | 静默清空/截断文件 |
| 4 | `find ... -exec rm/shred/del` | CRITICAL | 批量破坏（非 -delete 路径） |
| 5 | `$()` / `` ` `` 命令替换 | CRITICAL | 嵌套危险命令注入绕过 |
| 6 | `unlink` | HIGH | 直接删除 bypass 回收站 |
| 7 | `python/node -c` base64 载荷 | CRITICAL | 编码执行绕过审计 |

### 迁移方式

```
1. 复制 migrate-rules.yaml 中的 rules 条目
2. 追加到 ~/.jiuwenswarm/config/builtin_rules.yaml 的 rules: 列表
   （用户 config 目录下的 builtin_rules.yaml 优先级高于包内默认文件）
3. 移除 config.yaml 中 confirm-tools 的 Hook 配置
4. 重启 JiuwenSwarm
```

优势：规则与内置安全体系统一管理，tiered_policy 引擎直接处理，无子进程开销。用户 `builtin_rules.yaml` 中的规则会自动与包内默认规则合并。

### 迁移后效果

```
Agent 调用 bash
        │
        ▼
tiered_policy (权限引擎，进程内)
   ├─ 内置规则（builtin_rules.yaml: 10+7=17 条）
   ├─ 用户规则（permissions.rules）
   ├─ approval_overrides
   └─ external_directory
        │
        ├─ deny → 工具调用被拒绝
        ├─ ask  → 弹出确认框
        └─ allow → 放行
```

- confirm-tools Hook 配置可**安全移除**
- `confirm-tools.py` 脚本保留作为**归档参考**
- 所有检测逻辑由 `tiered_policy` 统一管理

### 相关文件

| 文件 | 用途 |
|---|---|
| `confirm-tools.py` | 原始 Hook 脚本（归档） |
| `migrate-rules.yaml` | 迁移规则，追加到 ~/.jiuwenswarm/config/builtin_rules.yaml |
| `README.md` | 本文档（含迁移指南） |
