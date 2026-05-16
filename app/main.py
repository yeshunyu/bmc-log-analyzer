import os
import re
import shutil
import uuid
import time
from pathlib import Path
from fastapi import FastAPI, UploadFile, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.errors import RateLimitExceeded as RateLimitExc
from app.limiters import limiter, llm_limiter, reanalyze_limiter
from app.auth import require_api_key
import threading

import json

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB upload limit

# Load version from build-injected file (set by Dockerfile ARG)
_version_file = Path(__file__).parent.parent / "app_version.json"
VERSION = json.loads(_version_file.read_text())["version"] if _version_file.exists() else "dev"


def _streaming_copy(src: UploadFile, dst_path: Path, max_size: int) -> int:
    """Stream file in chunks, aborting if max_size is exceeded. Returns bytes written."""
    written = 0
    chunk_size = 64 * 1024  # 64 KB
    with dst_path.open("wb") as f:
        while True:
            chunk = src.file.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            if written > max_size:
                dst_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail=f"文件超过 {max_size // (1024*1024)} MB 限制")
            f.write(chunk)
    return written


from app.routers.llm import router as llm_router
from app.operation_log import log_operation
from app.pipeline import LogAnalysisPipeline

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app):
    # Startup
    _n = _cleanup_old_files()
    if _n:
        print(f"[cleanup] Removed {_n} stale upload(s) on startup")
    _sync_manifest()
    _thread = threading.Thread(target=_cleanup_loop, daemon=True)
    _thread.start()
    yield
    # Shutdown: daemon thread exits with process


app = FastAPI(title="BMC Log Analyzer", lifespan=lifespan)
app.include_router(llm_router)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' data:;"
        )
        return response


# Validate CORS origins - reject wildcard in production
_cors_origins_env = os.environ.get("CORS_ORIGINS", "http://localhost:8000")
_cors_origins = [o.strip() for o in _cors_origins_env.split(",") if o.strip()]
if "*" in _cors_origins:
    import warnings
    warnings.warn("CORS_ORIGINS contains '*' which allows any origin. This is insecure for production!")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "请求过于频繁，请稍后再试（请稍候再试）"},
    )


STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MANIFEST_PATH = UPLOAD_DIR / "manifest.json"

# Files older than this many seconds are candidates for deletion
TTL_SECONDS = 24 * 3600  # 24 hours


def _load_manifest() -> list[dict]:
    """Returns list of {name, created_at, size}."""
    if not MANIFEST_PATH.exists():
        return []
    try:
        import json
        with MANIFEST_PATH.open() as f:
            return json.load(f)
    except Exception:
        return []


def _save_manifest(manifest: list[dict]) -> None:
    import json, tempfile, os
    # Atomic write: write to temp file then rename
    tmp = MANIFEST_PATH.with_suffix('.tmp')
    with tmp.open("w") as f:
        json.dump(manifest, f, ensure_ascii=False)
    tmp.rename(MANIFEST_PATH)


def _sync_manifest() -> None:
    """Remove entries whose files no longer exist; seed from disk if manifest is empty."""
    manifest = _load_manifest()
    current_files = {p.name for p in UPLOAD_DIR.iterdir()} if UPLOAD_DIR.exists() else set()
    # strip the uuid_ prefix to match manifest names
    kept = [e for e in manifest if f"{e['uuid']}_{e['name']}" in current_files]

    # If manifest is empty but there are files on disk, seed from disk (pre-feature uploads)
    if not kept and current_files:
        import re
        for fname in current_files:
            if fname == "manifest.json" or fname.endswith("_extract") or "_extract/" in fname:
                continue
            m = re.match(r'^([0-9a-f]{32})_(.+)$', fname)
            if m:
                uuid_part, orig_name = m.group(1), m.group(2)
                p = UPLOAD_DIR / fname
                if p.is_file():
                    kept.append({"uuid": uuid_part, "name": orig_name, "created_at": p.stat().st_mtime, "size": p.stat().st_size})

    if len(kept) != len(manifest):
        _save_manifest(kept)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(STATIC_DIR))


def _cleanup_old_files() -> int:
    """Delete files in UPLOAD_DIR older than TTL_SECONDS. Returns count deleted."""
    deleted = 0
    now = time.time()
    for p in UPLOAD_DIR.iterdir():
        try:
            if now - p.stat().st_mtime > TTL_SECONDS:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
                deleted += 1
        except OSError:
            pass
    if deleted:
        _sync_manifest()
    return deleted


def _cleanup_loop():
    """Background thread: clean up old uploads every 30 minutes."""
    while True:
        time.sleep(1800)  # 30 minutes
        n = _cleanup_old_files()
        if n:
            print(f"[cleanup] Removed {n} stale upload(s)")


@app.get("/", response_class=HTMLResponse)
async def index():
    return templates.get_template("index.html").render()


@app.get("/api/version")
async def get_version():
    return {"version": VERSION}


@app.post("/api/upload")
@limiter.limit("20/minute")
async def upload_log(request: Request, file: UploadFile, _auth: str = Depends(require_api_key)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".log", ".txt", ".gz", ".tar.gz", ""):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    # Sanitize filename: remove dangerous characters to prevent path traversal
    safe_name = re.sub(r'[^\w\-.]', '_', file.filename or 'unknown')
    safe_name = safe_name.replace('\x00', '')

    # Save uploaded file (streaming to disk, with size limit)
    job_id = uuid.uuid4().hex
    save_path = UPLOAD_DIR / f"{job_id}_{safe_name}"
    file_size = _streaming_copy(file, save_path, MAX_FILE_SIZE)

    # Record in manifest
    manifest = _load_manifest()
    manifest.insert(0, {"uuid": job_id, "name": safe_name, "created_at": time.time(), "size": file_size})
    _save_manifest(manifest[:20])

    # Run pipeline
    pipeline = LogAnalysisPipeline.from_upload(save_path, file.filename, job_id)
    result = pipeline.run()

    return result


@app.get("/api/history")
async def get_history(_auth: str = Depends(require_api_key)):
    """Return last 20 uploaded file names (without uuid prefix)."""
    _sync_manifest()
    manifest = _load_manifest()
    return [{"uuid": e["uuid"], "name": e["name"], "created_at": e["created_at"], "size": e["size"]} for e in manifest]


@app.delete("/api/history")
async def clear_history(_auth: str = Depends(require_api_key)):
    """Delete all history entries and their files from disk."""
    deleted = 0
    for p in UPLOAD_DIR.iterdir():
        try:
            if p.name.startswith("manifest"):
                continue
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            deleted += 1
        except Exception:
            pass
    if MANIFEST_PATH.exists():
        MANIFEST_PATH.unlink()
    log_operation(operation="clear_history", detail=f"清空全部历史，删除 {deleted} 个文件", result="ok")
    return {"deleted": deleted}


@app.get("/api/operation-logs")
async def get_operation_logs(days: int = 7, _auth: str = Depends(require_api_key)):
    """Return operation logs for the last N days (default 7)."""
    from app.operation_log import read_logs
    if days < 1 or days > 30:
        days = 7
    return read_logs(days=days)


@app.delete("/api/reanalyze/{uuid}")
@reanalyze_limiter.limit("5/minute")
async def delete_reanalyze(request: Request, uuid: str, _auth: str = Depends(require_api_key)):
    """Delete a previously uploaded file from disk and manifest."""
    # Validate UUID format (32 hex characters)
    if not re.match(r'^[a-f0-9]{32}$', uuid):
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    deleted = False
    original_name = ""
    for p in UPLOAD_DIR.iterdir():
        if p.name.startswith(f"{uuid}_"):
            original_name = p.name[len(uuid) + 1:]
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            deleted = True
            break
    if not deleted:
        raise HTTPException(status_code=404, detail="File not found")
    manifest = _load_manifest()
    manifest = [e for e in manifest if e["uuid"] != uuid]
    _save_manifest(manifest)
    log_operation(operation="delete_reanalyze", detail=f"删除历史文件 {uuid}", file_name=original_name, result="ok")
    return {"ok": True}


@app.post("/api/reanalyze/{uuid}")
@reanalyze_limiter.limit("5/minute")
async def reanalyze(request: Request, uuid: str, _auth: str = Depends(require_api_key)):
    """Re-run analysis on a previously uploaded file stored on disk."""
    if not re.match(r'^[a-f0-9]{32}$', uuid):
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    for p in UPLOAD_DIR.iterdir():
        if p.name.startswith(f"{uuid}_"):
            file_path = p
            original_name = p.name[len(uuid) + 1:]
            break
    else:
        raise HTTPException(status_code=404, detail="File not found (may have expired)")

    # Run pipeline (from_disk factory touches TTL timer)
    pipeline = LogAnalysisPipeline.from_disk(file_path, original_name, uuid)
    return pipeline.run()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, factory=True)
