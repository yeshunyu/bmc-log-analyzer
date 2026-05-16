## ADDED Requirements

### Requirement: ip-rate-limit
对指定 API 端点实施基于客户端 IP 的访问频率限制。

#### Scenario: normal request under limit
- **WHEN** 客户端在 1 分钟内请求次数未超过 60 次
- **THEN** 请求正常到达处理器，返回正常响应

#### Scenario: request over limit
- **WHEN** 客户端在 1 分钟内请求次数超过 60 次
- **THEN** 返回 HTTP 429 Too Many Requests，响应体包含 Retry-After 头

### Requirement: rate-limit-scope
限流仅作用于指定的敏感端点。

#### Scenario: non-sensitive endpoint
- **WHEN** 请求 `/api/history` 等非敏感端点
- **THEN** 不触发限流
