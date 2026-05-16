## Context

FastAPI 项目，使用 Uvicorn 运行。当前无任何访问频率控制。

## Goals / Non-Goals

**Goals:**
- 对 `/api/upload` 和 `/api/analyze/*` 增加 IP 级别的限流
- 默认限制：60 requests/minute per IP
- 超限返回 HTTP 429

**Non-Goals:**
- 不做用户级别的认证限流（V1）
- 不做分布式 Redis 存储（单机优先）

## Decisions

1. 使用 `slowapi` 库（基于 limits）
2. 限流规则在 `app/main.py` 中配置
3. 配置项放入 `app/config.py`

## Risks / Trade-offs

- 同一 NAT 下的多用户会共享 IP 限制
- 内存存储，重启后限制计数重置
