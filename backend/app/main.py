from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .admin_api import router as admin_router
from .auth_api import router as auth_router
from .database import Base, engine
from .web_auth import router as web_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Al-Farooq demo")

_u = urlparse(config.PUBLIC_URL)
ALLOWED_ORIGIN = f"{_u.scheme}://{_u.netloc}"


@app.middleware("http")
async def basic_protections(request: Request, call_next):
    # Browsers attach an Origin header to cross-site POSTs. If it is not our own
    # address, refuse. The desktop app sends no Origin, so it is not affected.
    origin = request.headers.get("origin")
    if request.method not in ("GET", "HEAD", "OPTIONS") and origin and origin != ALLOWED_ORIGIN:
        return JSONResponse({"detail": "Cross-site request blocked"}, status_code=403)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    if request.url.path.startswith("/web"):
        # our pages only load their own scripts and styles (no inline code)
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


app.include_router(auth_router)
app.include_router(web_router)
app.include_router(admin_router)
app.mount("/web", StaticFiles(directory=config.WEB_DIR, html=True), name="web")


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/web/register.html")
