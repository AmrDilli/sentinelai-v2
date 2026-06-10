"""SentinelAI v2 — FastAPI application.

Run:  uvicorn app.main:app --reload  (from the backend/ directory)
Docs: http://localhost:8000/docs
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

app = FastAPI(
    title="SentinelAI v2",
    description="AI-powered cybersecurity triage and response platform. "
                "Pipeline: Raw File → Parser → Pre-processor → AI Analysis → "
                "Scoring → Playbook → Dashboard.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {"name": "SentinelAI v2", "status": "ok", "docs": "/docs"}
