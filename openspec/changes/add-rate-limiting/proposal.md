## Why

当前 API 没有访问频率限制，恶意用户或异常客户端可能对服务造成压力。需要对关键 API 端点增加 rate limiting 保护。

## What Changes

对 `/api/upload` 和 `/api/analyze/*` 端点增加基于 IP 的访问频率限制。

## Capabilities

### New Capabilities
- `rate-limiting`: 基于 IP 的访问频率限制，防止滥用

### Modified Capabilities
- （无）

## Impact

- 新增依赖：`slowapi` 或同类的限流库
- 新增配置项：rate limit 参数
- 对超过限制的请求返回 429 Too Many Requests
