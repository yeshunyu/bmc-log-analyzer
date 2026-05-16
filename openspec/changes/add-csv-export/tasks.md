## 1. API 实现

- [ ] 1.1 在 `app/routers/` 下新建 `export.py`，实现 `GET /api/export/anomalies/{uuid}`
- [ ] 1.2 CSV 生成使用 Python csv 模块，StreamingHttpResponse 返回
- [ ] 1.3 路由注册到 `app/main.py`

## 2. Web UI 集成

- [ ] 2.1 在历史记录表格行末尾增加"导出 CSV"按钮
- [ ] 2.2 按钮调用 API 并触发浏览器下载

## 3. 测试

- [ ] 3.1 单元测试：CSV 生成字段完整性
- [ ] 3.2 手动验证：上传日志→检测异常→导出 CSV→Excel 打开验证
