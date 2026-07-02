from typing import Any

from fastapi import APIRouter, Request

from app.services.judge_service import judge_iocs


router = APIRouter(prefix="/api/v1/project/k01", tags=["k01"])


@router.post("/judge")
async def judge(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {
            "code": 40001,
            "message": "请求体不能为空",
            "total": 0,
            "success_count": 0,
            "failed_count": 0,
            "data": [],
        }

    if body is None:
        return {
            "code": 40001,
            "message": "请求体不能为空",
            "total": 0,
            "success_count": 0,
            "failed_count": 0,
            "data": [],
        }
    if not isinstance(body, dict) or "ioc" not in body:
        return {
            "code": 40002,
            "message": "缺少必填字段：ioc",
            "total": 0,
            "success_count": 0,
            "failed_count": 0,
            "data": [],
        }
    if not isinstance(body["ioc"], list):
        return {
            "code": 40003,
            "message": "ioc 必须是数组",
            "total": 0,
            "success_count": 0,
            "failed_count": 0,
            "data": [],
        }

    try:
        return judge_iocs(body["ioc"], project=body.get("project"))
    except Exception:
        return {
            "code": 50000,
            "message": "服务端异常",
            "total": len(body["ioc"]),
            "success_count": 0,
            "failed_count": 0,
            "data": [],
        }
