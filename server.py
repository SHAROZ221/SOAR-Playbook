"""
server.py
FastAPI web server for the SOAR-Playbook dashboard.
Provides API endpoints to ingest alerts, trigger dynamic playbooks,
stream execution logs in real time using SSE, and manage tickets.
"""

import os
import uuid
import json
import sqlite3
import asyncio
import threading
import hashlib
import secrets
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request, Response, Cookie
from fastapi.responses import StreamingResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    dotenv = None

from main import run_playbook, load_yaml, save_run_log

app = FastAPI(title="SOAR-Playbook Dashboard")

class SettingsPayload(BaseModel):
    abuseipdb_api_key: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

class LoginPayload(BaseModel):
    username: str
    password: str

# Simple in-memory session store
active_sessions = set()

# Helper: Hash password
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

# Helper: Get authentication credentials from .env
def get_auth_credentials():
    if dotenv and os.path.exists(ENV_PATH):
        dotenv.load_dotenv(ENV_PATH, override=True)
    admin_user = os.getenv("ADMIN_USER", "admin")
    # Default password hash for 'secflow123' if not set in .env
    default_hash = hash_password("secflow123")
    admin_pass_hash = os.getenv("ADMIN_PASSWORD_HASH", default_hash)
    return admin_user, admin_pass_hash


# Enable CORS for development convenience
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory dictionary to hold Server-Sent Events (SSE) queues for active runs
active_runs = {}

# Directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
PLAYBOOK_PATH = os.path.join(BASE_DIR, "playbook.yaml")
DB_PATH = os.path.join(BASE_DIR, "evidence", "tickets.db")
ENV_PATH = os.path.join(BASE_DIR, ".env")

def get_env_settings():
    if dotenv and os.path.exists(ENV_PATH):
        dotenv.load_dotenv(ENV_PATH, override=True)
    
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    tg_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    tg_chat = os.getenv("TELEGRAM_CHAT_ID", "")
    
    def mask_key(k):
        if not k:
            return ""
        if len(k) <= 8:
            return "********"
        return f"{k[:4]}...{k[-4:]}"
        
    return {
        "abuseipdb_api_key": mask_key(abuse_key),
        "telegram_bot_token": mask_key(tg_token),
        "telegram_chat_id": tg_chat,
    }

def write_env_settings(payload: SettingsPayload):
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            lines = f.readlines()
            
    env_dict = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env_dict[k.strip()] = v.strip()
            
    new_abuse = payload.abuseipdb_api_key.strip()
    if new_abuse and "..." not in new_abuse:
        env_dict["ABUSEIPDB_API_KEY"] = new_abuse
    elif not new_abuse:
        env_dict.pop("ABUSEIPDB_API_KEY", None)
        
    new_tg_token = payload.telegram_bot_token.strip()
    if new_tg_token and "..." not in new_tg_token:
        env_dict["TELEGRAM_BOT_TOKEN"] = new_tg_token
    elif not new_tg_token:
        env_dict.pop("TELEGRAM_BOT_TOKEN", None)
        
    new_tg_chat = payload.telegram_chat_id.strip()
    if new_tg_chat:
        env_dict["TELEGRAM_CHAT_ID"] = new_tg_chat
    else:
        env_dict.pop("TELEGRAM_CHAT_ID", None)
        
    with open(ENV_PATH, "w") as f:
        for k, v in env_dict.items():
            f.write(f"{k}={v}\n")
            
    if dotenv:
        dotenv.load_dotenv(ENV_PATH, override=True)


class AlertPayload(BaseModel):
    alert_id: str
    source: str
    rule_description: str
    indicator_type: str
    indicator_value: str
    affected_host: str
    raw_severity: str = "high"
    live_contain: bool = False


# Helper: Initialize SQLite DB (ensures database exists)
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            indicator TEXT,
            severity TEXT,
            status TEXT,
            created_at TEXT,
            summary TEXT
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


# Background task wrapper that executes the playbook
def execute_playbook_bg(alert: dict, playbook: dict, contain_mode: str, log_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    def log_callback(msg: str):
        # Thread-safe write to the asyncio queue
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, msg)

    try:
        run_log = run_playbook(alert, playbook, contain_mode=contain_mode, log_callback=log_callback)
        save_run_log(run_log)
        # Send completed tag with stringified JSON run_log
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, f"__COMPLETED__:{json.dumps(run_log)}")
    except Exception as e:
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, f"__FAILED__:Error running playbook: {e}")
    finally:
        # Send None to indicate end of queue
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, None)


# Helper: Validate Session
def get_session_user(session_id: str = Cookie(None)) -> str:
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Unauthorized session")
    return "admin"

@app.get("/login")
def login_page():
    login_path = os.path.join(WEB_DIR, "login.html")
    if not os.path.exists(login_path):
        raise HTTPException(status_code=404, detail="Login page not found.")
    return FileResponse(login_path)

@app.post("/api/auth/login")
def login_api(payload: LoginPayload, response: Response):
    expected_user, expected_hash = get_auth_credentials()
    if payload.username != expected_user or hash_password(payload.password) != expected_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    session_id = str(uuid.uuid4())
    active_sessions.add(session_id)
    # Set standard session cookie (lasts for session length)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False  # Allow HTTP in local dev
    )
    return {"status": "success"}

@app.post("/api/auth/logout")
def logout_api(response: Response, session_id: str = Cookie(None)):
    if session_id in active_sessions:
        active_sessions.remove(session_id)
    response.delete_cookie(key="session_id")
    return {"status": "success"}

@app.get("/api/auth/me")
def check_auth(session_id: str = Cookie(None)):
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"username": "admin"}

@app.get("/")
def read_root(session_id: str = Cookie(None)):
    """Serves the dashboard HTML interface if authenticated, else redirects to login."""
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/login")
        
    index_path = os.path.join(WEB_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Dashboard frontend (web/index.html) not found.")
    return FileResponse(index_path)


# Static stylesheet route
@app.get("/css/styles.css")
def read_css():
    css_path = os.path.join(WEB_DIR, "css", "styles.css")
    if not os.path.exists(css_path):
        raise HTTPException(status_code=404, detail="Stylesheet not found.")
    return FileResponse(css_path, media_type="text/css")


from fastapi import Depends

@app.post("/api/alerts")
async def trigger_playbook_endpoint(payload: AlertPayload, background_tasks: BackgroundTasks, user: str = Depends(get_session_user)):
    """
    Ingests a new alert, loads the default playbook,
    and spins up a background thread to run the playbook.
    """
    try:
      playbook = load_yaml(PLAYBOOK_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load playbook.yaml: {e}")

    alert_dict = payload.model_dump()
    contain_mode = "live" if payload.live_contain else "dry_run"

    # Generate execution run ID
    run_id = str(uuid.uuid4())
    log_queue = asyncio.Queue()
    active_runs[run_id] = log_queue

    # Start thread running the playbook
    loop = asyncio.get_running_loop()
    threading.Thread(
        target=execute_playbook_bg,
        args=(alert_dict, playbook, contain_mode, log_queue, loop),
        daemon=True
    ).start()

    return {"run_id": run_id}


@app.get("/api/runs/{run_id}/stream")
def stream_run_logs(run_id: str, user: str = Depends(get_session_user)):
    """
    Streams playbook execution output as Server-Sent Events (SSE).
    """
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail="Execution stream not found.")

    log_queue = active_runs[run_id]

    async def event_generator():
        try:
            while True:
                msg = await log_queue.get()
                if msg is None:
                    break
                yield f"data: {msg}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            # Clean up queue when client disconnects or finishes
            active_runs.pop(run_id, None)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/tickets")
def list_tickets(user: str = Depends(get_session_user)):
    """Returns all open and resolved tickets in the SQLite queue."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM tickets ORDER BY id DESC")
        tickets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return tickets
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


@app.post("/api/tickets/{ticket_id}/resolve")
def resolve_ticket(ticket_id: int, user: str = Depends(get_session_user)):
    """Marks a ticket as resolved."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("UPDATE tickets SET status = 'resolved' WHERE id = ?", (ticket_id,))
        conn.commit()
        changes = cursor.rowcount
        conn.close()
        if changes == 0:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        return {"status": "success", "resolved_id": ticket_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

@app.get("/api/settings")
def get_settings(user: str = Depends(get_session_user)):
    """Returns masked credentials stored in the local .env configuration."""
    try:
        return get_env_settings()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read settings: {e}")

@app.post("/api/settings")
def save_settings(payload: SettingsPayload, user: str = Depends(get_session_user)):
    """Saves credentials securely to .env and updates the current environment."""
    try:
        write_env_settings(payload)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)

