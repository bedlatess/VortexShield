from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.captcha import router as captcha_router
from app.api.routes.captcha import siteverify_router
from app.api.routes.home import router as home_router
from app.core.config import get_settings


settings = get_settings()

app = FastAPI(
    title=f"{settings.app_name} API",
    description="VortexShield intelligent behavioral captcha service.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(captcha_router, prefix="/api/captcha", tags=["captcha"])
app.include_router(siteverify_router, prefix="/api", tags=["siteverify"])
app.include_router(home_router, tags=["home"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
