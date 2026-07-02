# K01 API

## 本地启动

Excel 批处理：

```bash
python k01_run_process.py
# 或
python -m app.cli.excel_runner
```

API 服务：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

健康检查：

```bash
curl http://127.0.0.1:8000/healthz
```

批量 IOC 研判：

```bash
curl -X POST http://127.0.0.1:8000/api/v1/project/k01/judge \
  -H 'Content-Type: application/json' \
  -d '{"ioc":["maimai666.com","96.92.242.30:80","http://example.com/a/b"]}'
```

## 结构说明

- `app/core/process.py`：保留原 Excel 批处理和研判核心逻辑。
- `app/services/excel_service.py`：Excel 批处理服务入口。
- `app/services/judge_service.py`：接口版 IOC 研判编排，复用核心查询和规则函数。
- `app/cli/excel_runner.py`：新的 Excel 命令行入口。
- `k01_run_process.py`：兼容旧命令的薄入口，转调 `app.cli.excel_runner`。
- `app/main.py`：FastAPI 服务入口。
- `app/api/v1/judge.py`：接口路由和请求级校验。
- `app/services/validators.py`：单条 IOC 校验。
- `app/schemas/judge.py`：接口默认返回结构。

## 部署提醒

上线前建议把 `app/core/process.py` 中的 token、secret 和 URL 配置全部改为环境变量，并按服务器可承受能力调整并发参数。
