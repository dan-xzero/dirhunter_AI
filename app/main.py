from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import findings, scans, screenshots, stats, ws
from app.settings import settings


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, version="3.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            settings.effective_portal_url,
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(stats.router)
    app.include_router(screenshots.router)
    app.include_router(ws.router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
