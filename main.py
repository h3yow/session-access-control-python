"""FastAPI 入口（演示用）。核心能力在 authsys 包内，不依赖 Web 层。"""

from fastapi import FastAPI

app = FastAPI(title="session-access-control")


@app.get("/")
def read_root():
    return {"service": "session-access-control", "status": "ok"}
