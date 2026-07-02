from fastapi import FastAPI

from app.api.v1.judge import router as judge_router


app = FastAPI(title="K01 Intelligence Judgement API", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(judge_router)
