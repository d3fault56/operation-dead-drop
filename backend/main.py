"""OPERATION DEAD DROP — FastAPI backend."""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

import investigator
from demos import DEMOS

try:
    from dotenv import load_dotenv  # optional
    load_dotenv()
except ImportError:
    pass

MAX_CHARS = 10_000
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))

app = FastAPI(title="Operation Dead Drop API", version="1.0.0", docs_url="/docs")

origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def guard(request: Request, call_next):
    # request-size limit (defense in depth beyond pydantic)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_CHARS * 4 + 1024:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Request too large"}, status_code=413)
    if request.method == "POST":
        ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0].strip()
        q, now = _hits[ip], time.time()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Rate limit exceeded. Try again in a minute."}, status_code=429)
        q.append(now)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


class InvestigateRequest(BaseModel):
    content: str = Field(..., min_length=3, max_length=MAX_CHARS)
    demo_id: str | None = Field(default=None, max_length=32)
    offline: bool = False

    @field_validator("content")
    @classmethod
    def strip_controls(cls, v: str) -> str:
        v = "".join(ch for ch in v if ch in "\n\t" or ch >= " ")
        if not v.strip():
            raise ValueError("Content is empty")
        return v.strip()


@app.get("/health")
def health():
    return {"status": "ok", "ai_configured": bool(os.getenv("ANTHROPIC_API_KEY")), "model": investigator.MODEL}


@app.get("/demos")
def demos():
    return [{"id": k, **v} for k, v in DEMOS.items()]


@app.post("/investigate")
def investigate(req: InvestigateRequest):
    if req.demo_id and req.demo_id not in DEMOS:
        raise HTTPException(400, "Unknown demo")
    return investigator.investigate(req.content, demo_id=req.demo_id, force_offline=req.offline)


@app.get("/investigations/{op_id}")
def get_investigation(op_id: str):
    r = investigator.STORE.get(op_id.upper())
    if not r:
        raise HTTPException(404, "Operation not found")
    return r


@app.get("/investigations")
def list_investigations():
    return [{k: r[k] for k in ("operation_id", "timestamp", "threat_level", "attack_type", "input_type", "engine")}
            for r in reversed(list(investigator.STORE.values()))][:25]
