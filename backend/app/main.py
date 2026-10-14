from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analyze import router as analyze_router
from app.api.repositories import router as repositories_router
from app.api.review import router as review_router
from app.api.reports import router as reports_router
from app.api.build_logs import router as build_logs_router
from app.api.auth import router as auth_router
from app.core.config import settings


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0"
)

# CORS (React frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    auth_router,
    prefix="/api/auth",
    tags=["auth"]
)

app.include_router(
    analyze_router,
    prefix="/api"
)

app.include_router(
    repositories_router,
    prefix="/api/repositories",
    tags=["repositories"]
)

app.include_router(
    review_router,
    prefix="/api/review",
    tags=["review"]
)

app.include_router(
    reports_router,
    prefix="/api/reports",
    tags=["reports"]
)

app.include_router(
    build_logs_router,
    prefix="/api/build-log",
    tags=["build-log"]
)


@app.get("/health")
def health_check():
    return {"status": "ok"}
