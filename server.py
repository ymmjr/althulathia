from __future__ import annotations

import base64
import hashlib
import html
import json
import math
import os
import random
import re
import secrets
import socket
import sqlite3
import threading
import time
import uuid
import zipfile
from datetime import datetime
from itertools import combinations
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
QUESTIONS_PATH = ROOT / "Questions.json"
LOG_DIR = Path(os.environ.get("VAULT_LOG_DIR", str(ROOT / "Logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
VERSION = "Vault Web v0.40"



EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60

def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()[:254]

def hash_password(password: str, iterations: int = 310_000) -> str:
    password = str(password or "")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, base64.urlsafe_b64encode(salt).decode().rstrip("="), base64.urlsafe_b64encode(digest).decode().rstrip("="))

def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_b64, digest_b64 = str(stored).split("$", 3)
        if scheme != "pbkdf2_sha256": return False
        pad = lambda x: x + "=" * (-len(x) % 4)
        salt = base64.urlsafe_b64decode(pad(salt_b64))
        expected = base64.urlsafe_b64decode(pad(digest_b64))
        actual = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt, int(iters))
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False

def public_user(user: dict | None) -> dict | None:
    if not user: return None
    return {k: user.get(k) for k in ("id","email","name","role","status","created_at","approved_at","last_login_at")}


class Storage:
    """Durable room/event storage. SQLite locally, PostgreSQL when DATABASE_URL is present."""
    def __init__(self):
        self.database_url = os.environ.get("DATABASE_URL", "").strip()
        self.sqlite_path = Path(os.environ.get("VAULT_DB_PATH", str(ROOT / "vault_state.db")))
        self.kind = "postgres" if self.database_url.lower().startswith(("postgres://", "postgresql://")) else "sqlite"
        if self.kind == "sqlite":
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self.last_error = ""
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self):
        if self.kind == "postgres":
            try:
                import psycopg
            except Exception as e:
                raise RuntimeError("PostgreSQL requires psycopg. Install requirements.txt") from e
            return psycopg.connect(self.database_url, autocommit=True)
        con = sqlite3.connect(self.sqlite_path, timeout=30, check_same_thread=False)
        con.execute("PRAGMA busy_timeout=30000")
        return con

    def _init_schema(self):
        with self._lock:
            try:
                with self._connect() as con:
                    cur = con.cursor()
                    if self.kind == "sqlite":
                        cur.execute("PRAGMA journal_mode=WAL"); cur.execute("PRAGMA synchronous=FULL")
                    cur.execute("CREATE TABLE IF NOT EXISTS vault_rooms (code TEXT PRIMARY KEY, snapshot TEXT NOT NULL, updated_at TEXT NOT NULL)")
                    cur.execute("CREATE TABLE IF NOT EXISTS vault_events (room_code TEXT NOT NULL, event_no INTEGER NOT NULL, row_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(room_code,event_no))")
                    cur.execute("CREATE TABLE IF NOT EXISTS admin_users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, approved_at TEXT, approved_by TEXT, last_login_at TEXT)")
                    cur.execute("CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at BIGINT NOT NULL)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_admin_sessions_user ON admin_sessions(user_id)")
                    if self.kind == "sqlite": con.commit()
                self.last_error = ""
            except Exception as e:
                self.last_error = str(e)
                raise

    def save_room(self, snapshot: dict):
        payload = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            try:
                with self._connect() as con:
                    cur = con.cursor()
                    if self.kind == "postgres":
                        cur.execute("INSERT INTO vault_rooms(code,snapshot,updated_at) VALUES (%s,%s,%s) ON CONFLICT(code) DO UPDATE SET snapshot=EXCLUDED.snapshot, updated_at=EXCLUDED.updated_at", (snapshot["code"], payload, now))
                    else:
                        cur.execute("INSERT INTO vault_rooms(code,snapshot,updated_at) VALUES (?,?,?) ON CONFLICT(code) DO UPDATE SET snapshot=excluded.snapshot, updated_at=excluded.updated_at", (snapshot["code"], payload, now))
                        con.commit()
                self.last_error = ""
            except Exception as e:
                self.last_error = str(e)
                raise

    def append_event(self, room_code: str, event_no: int, row: list):
        payload = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            try:
                with self._connect() as con:
                    cur = con.cursor()
                    if self.kind == "postgres":
                        cur.execute("INSERT INTO vault_events(room_code,event_no,row_json,created_at) VALUES (%s,%s,%s,%s) ON CONFLICT(room_code,event_no) DO NOTHING", (room_code,event_no,payload,now))
                    else:
                        cur.execute("INSERT OR IGNORE INTO vault_events(room_code,event_no,row_json,created_at) VALUES (?,?,?,?)", (room_code,event_no,payload,now))
                        con.commit()
                self.last_error = ""
            except Exception as e:
                self.last_error = str(e)
                raise

    def load_rooms(self) -> list[dict]:
        with self._lock:
            try:
                with self._connect() as con:
                    cur = con.cursor(); cur.execute("SELECT snapshot FROM vault_rooms ORDER BY updated_at ASC")
                    rows = cur.fetchall()
                self.last_error = ""
                return [json.loads(r[0]) for r in rows]
            except Exception as e:
                self.last_error = str(e)
                raise

    def load_events(self, room_code: str) -> list[list]:
        with self._lock:
            try:
                with self._connect() as con:
                    cur = con.cursor()
                    if self.kind == "postgres": cur.execute("SELECT row_json FROM vault_events WHERE room_code=%s ORDER BY event_no", (room_code,))
                    else: cur.execute("SELECT row_json FROM vault_events WHERE room_code=? ORDER BY event_no", (room_code,))
                    rows = cur.fetchall()
                self.last_error = ""
                return [json.loads(r[0]) for r in rows]
            except Exception as e:
                self.last_error = str(e)
                raise

    def _fetchone(self, sql_pg: str, sql_sqlite: str, params=()):
        with self._lock:
            with self._connect() as con:
                cur = con.cursor(); cur.execute(sql_pg if self.kind == "postgres" else sql_sqlite, params); row = cur.fetchone()
            return row

    def superadmin_exists(self) -> bool:
        row = self._fetchone("SELECT 1 FROM admin_users WHERE role=%s AND status=%s LIMIT 1", "SELECT 1 FROM admin_users WHERE role=? AND status=? LIMIT 1", ("super_admin","approved"))
        return bool(row)

    def create_admin_user(self, email: str, name: str, password_hash: str, role="supervisor", status="pending") -> dict:
        user_id = uuid.uuid4().hex
        now = datetime.now().isoformat(timespec="seconds")
        email = normalize_email(email); name = " ".join(str(name or "").strip().split())[:120]
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                if self.kind == "postgres":
                    cur.execute("INSERT INTO admin_users(id,email,name,password_hash,role,status,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)", (user_id,email,name,password_hash,role,status,now))
                else:
                    cur.execute("INSERT INTO admin_users(id,email,name,password_hash,role,status,created_at) VALUES (?,?,?,?,?,?,?)", (user_id,email,name,password_hash,role,status,now)); con.commit()
        return self.get_admin_user_by_id(user_id)

    def get_admin_user_by_email(self, email: str) -> dict | None:
        row = self._fetchone("SELECT id,email,name,password_hash,role,status,created_at,approved_at,approved_by,last_login_at FROM admin_users WHERE email=%s", "SELECT id,email,name,password_hash,role,status,created_at,approved_at,approved_by,last_login_at FROM admin_users WHERE email=?", (normalize_email(email),))
        if not row: return None
        keys=("id","email","name","password_hash","role","status","created_at","approved_at","approved_by","last_login_at"); return dict(zip(keys,row))

    def get_admin_user_by_id(self, user_id: str) -> dict | None:
        row = self._fetchone("SELECT id,email,name,password_hash,role,status,created_at,approved_at,approved_by,last_login_at FROM admin_users WHERE id=%s", "SELECT id,email,name,password_hash,role,status,created_at,approved_at,approved_by,last_login_at FROM admin_users WHERE id=?", (str(user_id),))
        if not row: return None
        keys=("id","email","name","password_hash","role","status","created_at","approved_at","approved_by","last_login_at"); return dict(zip(keys,row))

    def list_admin_users(self) -> list[dict]:
        with self._lock:
            with self._connect() as con:
                cur=con.cursor(); cur.execute("SELECT id,email,name,role,status,created_at,approved_at,approved_by,last_login_at FROM admin_users ORDER BY created_at DESC"); rows=cur.fetchall()
        keys=("id","email","name","role","status","created_at","approved_at","approved_by","last_login_at")
        return [dict(zip(keys,r)) for r in rows]

    def set_admin_user_status(self, user_id: str, status: str, approved_by: str | None = None, role: str | None = None) -> dict | None:
        now = datetime.now().isoformat(timespec="seconds") if status == "approved" else None
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind == "postgres":
                    if role: cur.execute("UPDATE admin_users SET status=%s, role=%s, approved_at=%s, approved_by=%s WHERE id=%s", (status,role,now,approved_by,user_id))
                    else: cur.execute("UPDATE admin_users SET status=%s, approved_at=%s, approved_by=%s WHERE id=%s", (status,now,approved_by,user_id))
                else:
                    if role: cur.execute("UPDATE admin_users SET status=?, role=?, approved_at=?, approved_by=? WHERE id=?", (status,role,now,approved_by,user_id))
                    else: cur.execute("UPDATE admin_users SET status=?, approved_at=?, approved_by=? WHERE id=?", (status,now,approved_by,user_id))
                    con.commit()
        return self.get_admin_user_by_id(user_id)

    def touch_admin_login(self, user_id: str) -> None:
        now=datetime.now().isoformat(timespec="seconds")
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind == "postgres": cur.execute("UPDATE admin_users SET last_login_at=%s WHERE id=%s", (now,user_id))
                else: cur.execute("UPDATE admin_users SET last_login_at=? WHERE id=?", (now,user_id)); con.commit()

    def create_admin_session(self, user_id: str) -> str:
        token=secrets.token_urlsafe(32); token_hash=hashlib.sha256(token.encode()).hexdigest(); now=datetime.now().isoformat(timespec="seconds"); expires=int(time.time())+SESSION_TTL_SECONDS
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind == "postgres": cur.execute("INSERT INTO admin_sessions(token_hash,user_id,created_at,expires_at) VALUES (%s,%s,%s,%s)", (token_hash,user_id,now,expires))
                else: cur.execute("INSERT INTO admin_sessions(token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)", (token_hash,user_id,now,expires)); con.commit()
        return token

    def get_user_by_session(self, token: str) -> dict | None:
        if not token: return None
        token_hash=hashlib.sha256(str(token).encode()).hexdigest(); now=int(time.time())
        row=self._fetchone("SELECT u.id,u.email,u.name,u.password_hash,u.role,u.status,u.created_at,u.approved_at,u.approved_by,u.last_login_at,s.expires_at FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.token_hash=%s", "SELECT u.id,u.email,u.name,u.password_hash,u.role,u.status,u.created_at,u.approved_at,u.approved_by,u.last_login_at,s.expires_at FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.token_hash=?", (token_hash,))
        if not row: return None
        if int(row[-1]) < now:
            self.delete_admin_session(token); return None
        keys=("id","email","name","password_hash","role","status","created_at","approved_at","approved_by","last_login_at"); user=dict(zip(keys,row[:-1]))
        return user if user.get("status") == "approved" else None

    def delete_admin_session(self, token: str) -> None:
        if not token: return
        token_hash=hashlib.sha256(str(token).encode()).hexdigest()
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind == "postgres": cur.execute("DELETE FROM admin_sessions WHERE token_hash=%s", (token_hash,))
                else: cur.execute("DELETE FROM admin_sessions WHERE token_hash=?", (token_hash,)); con.commit()

    def delete_sessions_for_user(self, user_id: str) -> None:
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind == "postgres": cur.execute("DELETE FROM admin_sessions WHERE user_id=%s", (user_id,))
                else: cur.execute("DELETE FROM admin_sessions WHERE user_id=?", (user_id,)); con.commit()

    def health(self) -> dict:
        try:
            with self._connect() as con:
                cur = con.cursor(); cur.execute("SELECT 1"); cur.fetchone()
            self.last_error = ""
            return {"ok": True, "kind": self.kind}
        except Exception as e:
            self.last_error = str(e)
            return {"ok": False, "kind": self.kind, "error": self.last_error}

def excel_col(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s



def load_data() -> tuple[dict, list[dict]]:
    if not QUESTIONS_PATH.exists():
        raise FileNotFoundError(f"Questions.json not found: {QUESTIONS_PATH}")
    payload = json.loads(QUESTIONS_PATH.read_text(encoding="utf-8"))
    settings = payload.get("settings", {})
    config = {
        "game_title": str(settings.get("game_title", "الخزنة")),
        "question_seconds": int(settings.get("question_seconds", 10)),
        "storage_seconds": int(settings.get("storage_seconds", 5)),
        "port": 8080,
        "max_multiplier": max(1, int(settings.get("max_multiplier", 128))),
        "admin_pin": os.environ.get("VAULT_ADMIN_PIN", "2468"),
    }
    config["port"] = int(os.environ.get("PORT", os.environ.get("VAULT_PORT", config["port"])))
    config["question_seconds"] = int(os.environ.get("VAULT_QUESTION_SECONDS", config["question_seconds"]))
    config["storage_seconds"] = int(os.environ.get("VAULT_STORAGE_SECONDS", config["storage_seconds"]))

    questions = []
    for item in payload.get("questions", []):
        q = str(item.get("question", "")).strip()
        if not q:
            continue
        num = int(item.get("number"))
        difficulty = int(item.get("difficulty"))
        if difficulty not in {1, 2, 3}:
            raise ValueError(f"Invalid Difficulty for question {num}")
        questions.append({
            "number": num,
            "question": q,
            "correct_answer": str(item.get("correct_answer", "")).strip(),
            "difficulty": difficulty,
        })
    if not questions:
        raise RuntimeError("No questions found in Questions.json")
    if len({q["number"] for q in questions}) != len(questions):
        raise ValueError("Question Number values must be unique")
    if sum(1 for q in questions if q["difficulty"] == 3) != 2:
        raise ValueError("Questions.json must contain exactly two Difficulty=3 questions")
    return config, questions


def randomized_question_order(questions: list[dict]) -> list[dict]:
    items = [dict(q) for q in questions]
    hard = [q for q in items if q.get("difficulty") == 3]
    other = [q for q in items if q.get("difficulty") != 3]
    n = len(items)
    allowed_positions = list(range(1, n - 1))
    valid_positions = [p for p in combinations(allowed_positions, len(hard)) if all((b - a) > 1 for a, b in zip(p, p[1:]))]
    if not valid_positions:
        raise ValueError("Cannot place hard questions with current constraints")
    chosen = set(random.choice(valid_positions))
    random.shuffle(hard); random.shuffle(other)
    hi, oi = iter(hard), iter(other)
    return [next(hi) if i in chosen else next(oi) for i in range(n)]


def build_event_xlsx(rows: list[list[object]]) -> bytes:
    from io import BytesIO
    from xml.sax.saxutils import escape
    sheet_rows = []
    for r_idx, row in enumerate(rows, start=1):
        cells = []
        for c_idx, value in enumerate(row, start=1):
            ref = f"{excel_col(c_idx)}{r_idx}"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cells.append(f'<c r="{ref}" t="n"><v>{value}</v></c>')
            else:
                txt = escape("" if value is None else str(value))
                style = ' s="1"' if r_idx == 1 else ""
                cells.append(f'<c r="{ref}" t="inlineStr"{style}><is><t xml:space="preserve">{txt}</t></is></c>')
        sheet_rows.append(f'<row r="{r_idx}">{"".join(cells)}</row>')
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'''
    workbook = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="EventLog" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
    styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Arial"/></font><font><b/><sz val="11"/><name val="Arial"/></font></fonts><fills count="1"><fill><patternFill patternType="none"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'''
    sheet = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView rightToLeft="1" workbookViewId="0"/></sheetViews><sheetData>{''.join(sheet_rows)}</sheetData></worksheet>'''
    bio = BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return bio.getvalue()


def normalize_name(s: str) -> str:
    return " ".join(str(s).strip().split()).casefold()


def normalize_answer(s: str) -> str:
    return " ".join(str(s).strip().split()).casefold()


class GameRoom:
    LOG_HEADER = ["الوقت", "رقم الحدث", "رمز الغرفة", "رقم السؤال", "الفريق", "الحدث", "القيمة", "الخزنة قبل", "الخزنة بعد", "المعرض للخطر قبل", "المعرض للخطر بعد", "قيمة السؤال قبل", "قيمة السؤال بعد", "الإجابة", "التصحيح", "القرار", "ملاحظة"]
    EVENT_AR = {
        "ROOM_CREATED":"إنشاء الغرفة", "TEAM_JOINED":"انضمام فريق", "TEAM_REMOVED":"إزالة فريق", "JOIN_OPENED":"فتح الانضمام", "JOIN_CLOSED":"إغلاق الانضمام",
        "GAME_STARTED":"بدء الفقرة", "QUESTION_STARTED":"بدء السؤال", "ANSWER_SUBMITTED":"إرسال إجابة", "QUESTION_TIME_ENDED":"انتهاء وقت السؤال", "QUESTION_TIME_ENDED_MANUALLY":"إنهاء وقت السؤال يدويًا",
        "CORRECTION":"تصحيح الإجابة", "STORAGE_WINDOW_STARTED":"بدء مهلة التخزين", "STORAGE_BUTTON_PRESSED":"اختيار التخزين", "STORED":"تخزين النقاط", "RISK_CONTINUES":"استمرار المخاطرة",
        "QUESTION_RESOLVED":"اعتماد نتيجة السؤال", "MANUAL_ADD":"إضافة يدوية للخزنة", "MANUAL_DEDUCT":"خصم يدوي من الخزنة", "ROUND_RESET":"إعادة تهيئة الجولة", "GAME_FINISHED":"انتهاء الفقرة"
    }

    def __init__(self, config: dict, questions: list[dict], code: str, name: str, storage: Storage, restored: dict | None = None, owner_user_id: str = ""):
        self.cfg = dict(config)
        self.base_questions = [dict(q) for q in questions]
        self.storage = storage
        self.code = code
        self.name = name.strip() or f"غرفة {code}"
        self.admin_token = secrets.token_urlsafe(18)
        self.created_at = datetime.now().isoformat(timespec="seconds")
        self.owner_user_id = str(owner_user_id or "")
        self.archived_at = None
        self.lock = threading.RLock()
        self.cv_team = threading.Condition(self.lock)
        self.cv_admin = threading.Condition(self.lock)
        self.cv_display = threading.Condition(self.lock)
        self.rev_team = 1
        self.rev_admin = 1
        self.rev_display = 1
        self._dirty = False
        self._last_persist_ms = 0
        self.teams: dict[str, dict] = {}
        self.team_token_index: dict[str, str] = {}
        self.log_rows = [list(self.LOG_HEADER)]
        self._event_no = 0
        if restored:
            self._restore(restored)
            events = self.storage.load_events(self.code)
            self.log_rows = [list(self.LOG_HEADER)] + events
            self._event_no = max([int(r[1]) for r in events if len(r) > 1 and str(r[1]).isdigit()] or [0])
        else:
            self._init_round(clear_scores=True)
            self._event("SYSTEM", "ROOM_CREATED", note=f"إنشاء {self.name}")

    def _restore(self, d: dict) -> None:
        self.name = str(d.get("name", self.name))
        self.admin_token = str(d.get("admin_token") or self.admin_token)
        self.created_at = str(d.get("created_at") or self.created_at)
        self.owner_user_id = str(d.get("owner_user_id") or self.owner_user_id or "")
        self.archived_at = d.get("archived_at")
        self.questions = [dict(q) for q in d.get("questions", self.base_questions)]
        self.phase = str(d.get("phase", "lobby"))
        self.game_started = bool(d.get("game_started", False))
        self.joins_open = bool(d.get("joins_open", True))
        self.index = int(d.get("index", -1))
        self.question_deadline_ms = int(d.get("question_deadline_ms", 0))
        self.storage_deadline_ms = int(d.get("storage_deadline_ms", 0))
        self.question_token = int(d.get("question_token", 0))
        self.closed_question_deadline_ms = int(d.get("closed_question_deadline_ms", 0))
        self.correction_ready_ms = int(d.get("correction_ready_ms", 0))
        raw_teams = d.get("teams", {})
        self.teams = {str(k): dict(v) for k, v in raw_teams.items()} if isinstance(raw_teams, dict) else {}
        self.team_token_index = {str(t.get("token")): tid for tid, t in self.teams.items() if t.get("token")}

    def snapshot(self) -> dict:
        return {
            "schema": 2, "code": self.code, "name": self.name, "admin_token": self.admin_token, "created_at": self.created_at, "owner_user_id": self.owner_user_id, "archived_at": self.archived_at,
            "questions": self.questions, "phase": self.phase, "game_started": self.game_started, "joins_open": self.joins_open, "index": self.index,
            "question_deadline_ms": self.question_deadline_ms, "storage_deadline_ms": self.storage_deadline_ms, "question_token": self.question_token,
            "closed_question_deadline_ms": self.closed_question_deadline_ms, "correction_ready_ms": self.correction_ready_ms, "teams": self.teams,
        }

    def _persist(self) -> None:
        self.storage.save_room(self.snapshot())
        self._dirty = False
        self._last_persist_ms = self._now_ms()

    def flush_dirty(self, force=False) -> None:
        with self.lock:
            if self._dirty and (force or self._now_ms() - self._last_persist_ms >= 250):
                self._persist()

    def _changed(self, team=False, admin=False, display=False, persist=True) -> None:
        if persist:
            self._persist()
        else:
            self._dirty = True
        if team:
            self.rev_team += 1; self.cv_team.notify_all()
        if admin:
            self.rev_admin += 1; self.cv_admin.notify_all()
        if display:
            self.rev_display += 1; self.cv_display.notify_all()

    def _revision(self, channel: str) -> int:
        return {"team": self.rev_team, "admin": self.rev_admin, "display": self.rev_display}[channel]

    def wait_revision(self, channel: str, last_revision: int, timeout: float = 15.0) -> int:
        cond = {"team": self.cv_team, "admin": self.cv_admin, "display": self.cv_display}[channel]
        with cond:
            if self._revision(channel) == last_revision:
                cond.wait(timeout=timeout)
            return self._revision(channel)

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _init_round(self, clear_scores: bool) -> None:
        self.questions = randomized_question_order(self.base_questions)
        self.phase = "lobby"
        self.game_started = False
        self.joins_open = True
        self.index = -1
        self.question_deadline_ms = 0
        self.storage_deadline_ms = 0
        self.question_token = 0
        self.closed_question_deadline_ms = 0
        self.correction_ready_ms = 0
        for team in self.teams.values():
            if clear_scores:
                team["vault"] = 0; team["risk"] = 0; team["value"] = 1
            self._clear_question_team(team)

    def _clear_question_team(self, team: dict) -> None:
        team["draft"] = ""
        team["draft_revision"] = 0
        team["answer"] = ""
        team["submitted"] = False
        team["auto_finalized"] = False
        team["correction"] = None
        team["decision"] = None

    def _team_label(self, team_id: str) -> str:
        if team_id == "SYSTEM": return "النظام"
        t = self.teams.get(team_id)
        return t["name"] if t else str(team_id)

    def _event(self, team_id: str, event_type: str, value="", vault_before="", vault_after="", risk_before="", risk_after="", multiplier_before="", multiplier_after="", answer="", correct="", decision="", note="") -> None:
        self._event_no += 1
        q = self.current_question()
        qno = q.get("number", "") if q else ""
        row = [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self._event_no, self.code, qno, self._team_label(team_id), self.EVENT_AR.get(event_type, event_type), value, vault_before, vault_after, risk_before, risk_after, multiplier_before, multiplier_after, answer, correct, {"store":"تخزين","risk":"مخاطرة","wrong":"إجابة خاطئة"}.get(decision, decision), note]
        self.log_rows.append(row)
        # Database is the durable source of truth for the event log. JSONL remains a local readable backup.
        try:
            self.storage.append_event(self.code, self._event_no, row)
        except Exception as e:
            print(f"[STORAGE] event append failed for {self.code}: {e}")
        try:
            with (LOG_DIR / f"Vault_{self.code}_events.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(dict(zip(self.LOG_HEADER, row)), ensure_ascii=False) + "\n")
        except Exception:
            pass

    def current_question(self):
        return self.questions[self.index] if 0 <= self.index < len(self.questions) else None

    def validate_team_token(self, token: str) -> dict | None:
        team_id = self.team_token_index.get(str(token))
        if not team_id:
            return None
        return self.teams.get(team_id)

    def join_team(self, name: str, existing_token: str = ""):
        with self.lock:
            name = " ".join(str(name).strip().split())[:80]
            if not name:
                return False, "اكتب اسم الفريق.", None
            norm = normalize_name(name)
            existing = next((t for t in self.teams.values() if t["name_norm"] == norm), None)
            if existing:
                if existing_token and secrets.compare_digest(existing.get("token", ""), str(existing_token)):
                    existing["last_seen_ms"] = self._now_ms()
                    return True, "تم استعادة دخول الفريق.", existing
                return False, "اسم الفريق مستخدم بالفعل داخل هذه الغرفة. استخدم الجهاز الذي سجّل الفريق أول مرة أو اختر اسمًا آخر.", None
            if not self.joins_open or self.game_started or self.phase != "lobby":
                return False, "أُغلق الانضمام لهذه الجولة.", None
            team_id = uuid.uuid4().hex[:12]
            token = secrets.token_urlsafe(20)
            team = {
                "id": team_id, "token": token, "name": name, "name_norm": norm,
                "joined_at": datetime.now().isoformat(timespec="seconds"), "last_seen_ms": self._now_ms(),
                "vault": 0, "risk": 0, "value": 1,
            }
            self._clear_question_team(team)
            self.teams[team_id] = team
            self.team_token_index[token] = team_id
            self._event(team_id, "TEAM_JOINED", note="انضم الفريق من صفحة الدخول العامة")
            self._changed(team=True, admin=True, display=True)
            return True, "تم الانضمام للغرفة.", team

    def remove_team(self, team_id: str):
        with self.lock:
            if self.game_started or self.phase != "lobby": return False, "يمكن إزالة الفرق فقط قبل بدء الجولة."
            team = self.teams.get(team_id)
            if not team: return False, "الفريق غير موجود."
            self._event(team_id, "TEAM_REMOVED", note="أزال المشرف الفريق قبل بدء الجولة")
            self.team_token_index.pop(team["token"], None)
            self.teams.pop(team_id, None)
            self._changed(team=True, admin=True, display=True)
            return True, "تمت إزالة الفريق."

    def set_join_open(self, open_value: bool):
        with self.lock:
            if self.game_started or self.phase != "lobby": return False, "لا يمكن تغيير الانضمام بعد بدء الجولة."
            self.joins_open = bool(open_value)
            self._event("SYSTEM", "JOIN_OPENED" if self.joins_open else "JOIN_CLOSED")
            self._changed(team=True, admin=True, display=True)
            return True, "تم فتح الانضمام." if self.joins_open else "تم إغلاق الانضمام."

    def reset_round(self):
        with self.lock:
            self.archived_at = None
            self._init_round(clear_scores=True)
            self._event("SYSTEM", "ROUND_RESET", note="إعادة جميع الفرق إلى Lobby وتصفير الجولة")
            self._changed(team=True, admin=True, display=True)
            return True, "تمت إعادة تهيئة الجولة وفتح الانضمام."

    def start_game(self):
        with self.lock:
            if self.game_started: return False, "الجولة بدأت بالفعل."
            if not self.teams: return False, "لا يوجد أي فريق داخل الغرفة."
            self.joins_open = False
            self.game_started = True
            self.phase = "ready"
            self._event("SYSTEM", "JOIN_CLOSED", note="إغلاق تلقائي عند بدء الجولة")
            self._event("SYSTEM", "GAME_STARTED", value=len(self.teams), note="بدأت فقرة الخزنة")
            return self.start_next()

    def _finalize_unsubmitted_from_drafts(self):
        for t in self.teams.values():
            if t["submitted"]: continue
            final = t["draft"].strip()[:500]
            t["answer"] = final
            t["auto_finalized"] = bool(final)

    def tick(self):
        with self.lock:
            now = self._now_ms()
            if self.phase == "question_open" and now >= self.question_deadline_ms:
                self.closed_question_deadline_ms = self.question_deadline_ms
                self._finalize_unsubmitted_from_drafts()
                self.phase = "waiting_correction"
                self.question_deadline_ms = 0
                self.correction_ready_ms = self.closed_question_deadline_ms + 400
                self._event("SYSTEM", "QUESTION_TIME_ENDED", note="انتهى الوقت واعتمد آخر Draft لغير المرسلين")
                self._changed(team=True, admin=True, display=True)
            if self.phase == "storage_open" and now >= self.storage_deadline_ms:
                self._finalize_storage()

    def start_next(self):
        with self.lock:
            self.tick()
            if not self.game_started: return False, "ابدأ الجولة أولًا."
            if self.phase not in {"ready", "resolved"}: return False, "لا يمكن بدء سؤال جديد قبل انتهاء المرحلة الحالية."
            if self.index + 1 >= len(self.questions):
                self.phase = "finished"
                self.archived_at = self.archived_at or datetime.now().isoformat(timespec="seconds")
                self._event("SYSTEM", "GAME_FINISHED", note="انتهت فقرة الخزنة")
                self._changed(team=True, admin=True, display=True)
                return True, "انتهت الفقرة."
            self.index += 1
            self.question_token += 1
            for t in self.teams.values(): self._clear_question_team(t)
            self.phase = "question_open"
            self.question_deadline_ms = self._now_ms() + self.cfg["question_seconds"] * 1000
            self.closed_question_deadline_ms = 0; self.correction_ready_ms = 0; self.storage_deadline_ms = 0
            q = self.current_question() or {}
            self._event("SYSTEM", "QUESTION_STARTED", value=self.index + 1, note=f"ترتيب السؤال: {self.index+1}; رقم السؤال: {q.get('number','')}; عدد الفرق: {len(self.teams)}")
            self._changed(team=True, admin=True, display=True)
            return True, "بدأ السؤال."

    def close_question_now(self):
        with self.lock:
            self.tick()
            if self.phase != "question_open": return False, "السؤال غير مفتوح الآن."
            now = self._now_ms()
            self.closed_question_deadline_ms = now
            self._finalize_unsubmitted_from_drafts()
            self.phase = "waiting_correction"
            self.question_deadline_ms = 0
            self.correction_ready_ms = now + 300
            self._event("SYSTEM", "QUESTION_TIME_ENDED_MANUALLY", note="أنهى المشرف وقت الإجابة واعتمد آخر Draft")
            self._changed(team=True, admin=True, display=True)
            return True, "تم إنهاء وقت السؤال."

    def update_draft(self, team: dict, draft, revision, question_token):
        with self.lock:
            try: revision = int(revision); question_token = int(question_token)
            except Exception: return False, "بيانات المسودة غير صحيحة."
            if question_token != self.question_token: return False, "هذه المسودة تخص سؤالًا سابقًا."
            if team["submitted"]: return False, "تم إرسال الإجابة وإغلاقها."
            self.tick()
            if revision <= team["draft_revision"]: return True, "تم تجاهل تحديث أقدم."
            text = str(draft)[:500]
            if self.phase == "question_open":
                team["draft"] = text; team["draft_revision"] = revision; team["last_seen_ms"] = self._now_ms()
                self._changed(admin=True, persist=False)
                return True, "تم تحديث المسودة."
            now = self._now_ms()
            if self.phase == "waiting_correction" and now <= self.correction_ready_ms:
                team["draft"] = text; team["draft_revision"] = revision; team["answer"] = text.strip()[:500]; team["auto_finalized"] = bool(team["answer"]); team["last_seen_ms"] = now
                self._changed(admin=True, persist=False)
                return True, "تم اعتماد آخر مسودة وصلت عند نهاية الوقت."
            return False, "انتهى وقت تعديل الإجابة."

    def submit_answer(self, team: dict, answer: str):
        with self.lock:
            self.tick()
            if self.phase != "question_open": return False, "انتهى وقت الإجابة."
            if team["submitted"]: return False, "تم إرسال الإجابة مسبقًا."
            answer = str(answer).strip()
            if not answer: return False, "اكتب الإجابة أولًا."
            team["answer"] = answer[:500]; team["draft"] = team["answer"]; team["submitted"] = True; team["auto_finalized"] = False; team["last_seen_ms"] = self._now_ms()
            self._event(team["id"], "ANSWER_SUBMITTED", answer=team["answer"], note="تم الإرسال وقفل الإجابة فورًا")
            self._changed(admin=True, display=True)
            return True, "تم استلام الإجابة."

    def apply_corrections(self, corrections: dict):
        with self.lock:
            self.tick()
            if self.phase != "waiting_correction": return False, "التصحيح غير متاح الآن."
            if self._now_ms() < self.correction_ready_ms: return False, "جاري تثبيت آخر كتابة وصلت؛ أعد المحاولة بعد لحظة."
            expected = set(self.teams.keys())
            if set(corrections.keys()) != expected or not all(isinstance(v, bool) for v in corrections.values()):
                return False, "يجب تصحيح جميع الفرق قبل الاعتماد."
            any_correct = False
            final_q = self.index == len(self.questions) - 1
            for team_id, t in self.teams.items():
                t["correction"] = corrections[team_id]
                vb, rb, mb = t["vault"], t["risk"], t["value"]
                if t["correction"]:
                    any_correct = True
                    t["risk"] += t["value"]
                    t["decision"] = None
                    note = f"أضيفت قيمة السؤال الحالية ({t['value']}) إلى النقاط المعرضة للخطر"
                else:
                    t["risk"] = 0; t["value"] = 1; t["decision"] = "wrong"
                    note = "إجابة خاطئة: تصفير المعرض للخطر وإعادة قيمة السؤال إلى 1"
                self._event(team_id, "CORRECTION", value=mb if t["correction"] else 0, vault_before=vb, vault_after=t["vault"], risk_before=rb, risk_after=t["risk"], multiplier_before=mb, multiplier_after=t["value"], answer=t["answer"], correct="صحيح" if t["correction"] else "خطأ", decision=t["decision"] or "", note=note)
            if final_q:
                for team_id, t in self.teams.items():
                    if not t["correction"]: continue
                    vb, rb, mb = t["vault"], t["risk"], t["value"]; stored = t["risk"]
                    t["vault"] += stored; t["risk"] = 0; t["value"] = 1; t["decision"] = "store"
                    self._event(team_id, "STORED", value=stored, vault_before=vb, vault_after=t["vault"], risk_before=rb, risk_after=0, multiplier_before=mb, multiplier_after=1, correct="صحيح", decision="store", note="السؤال الأخير: تخزين تلقائي")
                self.phase = "finished"; self.storage_deadline_ms = 0
                self.archived_at = self.archived_at or datetime.now().isoformat(timespec="seconds")
                self._event("SYSTEM", "QUESTION_RESOLVED", note="تم اعتماد نتيجة السؤال الأخير")
                self._event("SYSTEM", "GAME_FINISHED", note="انتهت الفقرة بعد السؤال الأخير")
                self._changed(team=True, admin=True, display=True)
                return True, "تم اعتماد التصحيح وتخزين السؤال الأخير تلقائيًا. انتهت الفقرة."
            if any_correct:
                self.phase = "storage_open"
                self.storage_deadline_ms = self._now_ms() + self.cfg["storage_seconds"] * 1000
                self._event("SYSTEM", "STORAGE_WINDOW_STARTED", value=self.cfg["storage_seconds"], note="بدأت مهلة التخزين المشتركة لكل الفرق الصحيحة")
            else:
                self.phase = "resolved"
                self._event("SYSTEM", "QUESTION_RESOLVED", note="انتهى السؤال دون مرحلة تخزين")
            self._changed(team=True, admin=True, display=True)
            return True, "تم اعتماد تصحيح جميع الفرق."

    def choose_storage(self, team: dict):
        with self.lock:
            self.tick()
            if self.phase != "storage_open": return False, "انتهت مرحلة التخزين."
            if not team.get("correction"): return False, "لا يوجد خيار تخزين لهذا الفريق."
            if team.get("decision") is not None: return False, "تم تسجيل القرار مسبقًا."
            team["decision"] = "store"
            self._event(team["id"], "STORAGE_BUTTON_PRESSED", vault_before=team["vault"], vault_after=team["vault"], risk_before=team["risk"], risk_after=team["risk"], multiplier_before=team["value"], multiplier_after=team["value"], decision="store", note="تم تسجيل اختيار التخزين")
            self._changed(admin=True, display=True)
            return True, "تم تسجيل قرار التخزين."

    def _finalize_storage(self):
        if self.phase != "storage_open": return
        cap = int(self.cfg.get("max_multiplier", 128))
        for team_id, t in self.teams.items():
            if not t.get("correction"): continue
            vb, rb, mb = t["vault"], t["risk"], t["value"]
            if t.get("decision") == "store":
                t["vault"] += t["risk"]; t["risk"] = 0; t["value"] = 1
                decision = "store"; event = "STORED"; val = t["vault"] - vb; note = "تم نقل جميع النقاط المعرضة للخطر إلى الخزنة"
            else:
                t["decision"] = "risk"; t["value"] = min(t["value"] * 2, cap)
                decision = "risk"; event = "RISK_CONTINUES"; val = t["value"]; note = f"استمرت المخاطرة؛ قيمة السؤال التالي {t['value']}"
            self._event(team_id, event, value=val, vault_before=vb, vault_after=t["vault"], risk_before=rb, risk_after=t["risk"], multiplier_before=mb, multiplier_after=t["value"], correct="صحيح", decision=decision, note=note)
        self.phase = "resolved"; self.storage_deadline_ms = 0
        self._event("SYSTEM", "QUESTION_RESOLVED", note="تم اعتماد نتيجة السؤال")
        self._changed(team=True, admin=True, display=True)

    def adjust_vault(self, team_id: str, mode: str, amount):
        with self.lock:
            t = self.teams.get(team_id)
            if not t: return False, "الفريق غير موجود."
            try: amount = int(amount)
            except Exception: return False, "القيمة غير صحيحة."
            if amount <= 0 or mode not in {"add", "deduct"}: return False, "القيمة أو نوع التعديل غير صحيح."
            before = t["vault"]
            if mode == "add": t["vault"] += amount; actual = amount; event = "MANUAL_ADD"
            else: actual = min(amount, t["vault"]); t["vault"] -= actual; event = "MANUAL_DEDUCT"
            self._event(team_id, event, value=actual if mode == "add" else -actual, vault_before=before, vault_after=t["vault"], risk_before=t["risk"], risk_after=t["risk"], multiplier_before=t["value"], multiplier_after=t["value"], note="تعديل يدوي من المشرف")
            self._changed(team=True, admin=True, display=True)
            return True, f"تم {'إضافة' if mode=='add' else 'خصم'} {actual} نقطة."

    def phase_ar(self):
        return {"lobby":"بانتظار الفرق", "ready":"جاهز", "question_open":"وقت الإجابة", "waiting_correction":"بانتظار التصحيح", "storage_open":"وقت التخزين", "resolved":"تم اعتماد النتيجة", "finished":"انتهت الفقرة"}.get(self.phase, self.phase)

    def team_status(self, t: dict):
        if self.phase == "lobby": return "داخل الغرفة"
        if self.phase == "question_open": return "تم إرسال الإجابة" if t["submitted"] else ("يكتب الآن" if t["draft"] else "بانتظار الإجابة")
        if self.phase == "waiting_correction": return "بانتظار التصحيح"
        if self.phase == "storage_open":
            return ("تم اختيار التخزين" if t["decision"] == "store" else "بانتظار قرار التخزين") if t.get("correction") else "إجابة خاطئة"
        if self.phase == "resolved": return {"store":"خزّن", "risk":"خاطر", "wrong":"إجابة خاطئة"}.get(t.get("decision"), "تم")
        if self.phase == "finished": return "انتهت الفقرة"
        return "جاهز"

    def leaderboard(self, limit=10):
        teams = list(self.teams.values())
        teams.sort(key=lambda t: (-t["vault"], -t["risk"], normalize_name(t["name"])))
        return [{"rank":i+1, "id":t["id"], "name":t["name"], "vault":t["vault"], "risk":t["risk"], "value":t["value"]} for i,t in enumerate(teams[:limit])]

    def public_summary(self):
        with self.lock:
            self.tick()
            return {"ok": True, "code": self.code, "name": self.name, "phase": self.phase, "phase_ar": self.phase_ar(), "joins_open": self.joins_open, "game_started": self.game_started, "team_count": len(self.teams)}

    def team_state(self, team: dict):
        with self.lock:
            self.tick(); now = self._now_ms(); q = self.current_question()
            team["last_seen_ms"] = now
            return {
                "room_code": self.code, "room_name": self.name, "phase": self.phase, "phase_ar": self.phase_ar(), "joins_open": self.joins_open,
                "server_now_ms": now, "question_deadline_ms": self.question_deadline_ms, "storage_deadline_ms": self.storage_deadline_ms,
                "question_no": self.index + 1 if self.index >= 0 else 0, "total_questions": len(self.questions), "question_token": self.question_token,
                "question": q["question"] if q and self.phase == "question_open" else "", "team_count": len(self.teams),
                "team": {"id":team["id"], "name":team["name"], "vault":team["vault"], "risk":team["risk"], "value":team["value"], "submitted":team["submitted"], "auto_finalized":team["auto_finalized"], "correction":team["correction"], "decision":team["decision"], "answer":team["answer"], "status":self.team_status(team)},
                "max_multiplier": self.cfg["max_multiplier"]
            }

    def admin_state(self):
        with self.lock:
            self.tick(); now = self._now_ms(); q = self.current_question()
            teams = []
            for t in sorted(self.teams.values(), key=lambda x: normalize_name(x["name"])):
                teams.append({
                    "id":t["id"], "name":t["name"], "vault":t["vault"], "risk":t["risk"], "value":t["value"], "draft":t["draft"], "answer":t["answer"],
                    "submitted":t["submitted"], "auto_finalized":t["auto_finalized"], "correction":t["correction"], "decision":t["decision"], "status":self.team_status(t),
                    "last_seen_ms": t["last_seen_ms"]
                })
            groups = []
            if self.phase == "waiting_correction":
                bucket = {}
                for t in teams:
                    key = normalize_answer(t["answer"])
                    bucket.setdefault(key, {"answer": t["answer"] or "— بدون إجابة —", "team_ids": [], "team_names": []})
                    bucket[key]["team_ids"].append(t["id"]); bucket[key]["team_names"].append(t["name"])
                groups = sorted(bucket.values(), key=lambda g: (-len(g["team_ids"]), g["answer"]))
            return {
                "room_code":self.code, "room_name":self.name, "created_at":self.created_at, "archived_at":self.archived_at, "owner_user_id":self.owner_user_id, "phase":self.phase, "phase_ar":self.phase_ar(), "joins_open":self.joins_open, "game_started":self.game_started,
                "server_now_ms":now, "question_deadline_ms":self.question_deadline_ms, "storage_deadline_ms":self.storage_deadline_ms, "correction_ready_ms":self.correction_ready_ms,
                "question_no":self.index+1 if self.index>=0 else 0, "total_questions":len(self.questions), "question_token":self.question_token,
                "question":q["question"] if q else "", "correct_answer":q["correct_answer"] if q else "", "difficulty":q["difficulty"] if q else 0,
                "team_count":len(teams), "teams":teams, "answer_groups":groups, "leaderboard":self.leaderboard(10), "max_multiplier":self.cfg["max_multiplier"]
            }

    def display_state(self):
        with self.lock:
            self.tick(); now = self._now_ms(); q = self.current_question(); total = len(self.teams)
            submitted = sum(1 for t in self.teams.values() if t["submitted"])
            answered = sum(1 for t in self.teams.values() if t["answer"] or t["draft"])
            correct = sum(1 for t in self.teams.values() if t.get("correction") is True)
            storage_waiting = sum(1 for t in self.teams.values() if t.get("correction") is True and t.get("decision") is None)
            if self.phase == "question_open":
                headline = q["question"] if q else ""
                timer = max(0, math.ceil((self.question_deadline_ms-now)/1000))
                subline = f"تم الإرسال: {submitted} / {total}"
            elif self.phase == "waiting_correction":
                headline = "انتهى وقت الإجابة"
                timer = 0; subline = f"تم استلام إجابة من {answered} / {total} فريقًا — بانتظار التصحيح"
            elif self.phase == "storage_open":
                headline = "وقت التخزين"
                timer = max(0, math.ceil((self.storage_deadline_ms-now)/1000))
                subline = f"إجابات صحيحة: {correct} — بانتظار قرار {storage_waiting} فريقًا"
            elif self.phase == "resolved":
                headline = "تم اعتماد نتيجة السؤال"
                timer = 0; subline = "الترتيب الحالي"
            elif self.phase == "finished":
                headline = "انتهت فقرة الخزنة"
                timer = 0; subline = "الترتيب النهائي"
            else:
                headline = self.name
                timer = 0; subline = f"رمز الغرفة: {self.code} — {total} فريقًا منضمًا"
            return {"room_code":self.code, "room_name":self.name, "phase":self.phase, "phase_ar":self.phase_ar(), "server_now_ms":now, "question_deadline_ms":self.question_deadline_ms, "storage_deadline_ms":self.storage_deadline_ms, "question_no":self.index+1 if self.index>=0 else 0, "total_questions":len(self.questions), "headline":headline, "subline":subline, "timer":timer, "team_count":total, "submitted_count":submitted, "leaderboard":self.leaderboard(10)}


class RoomManager:
    ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def __init__(self, config, questions):
        self.cfg = config; self.questions = questions; self.rooms: dict[str, GameRoom] = {}; self.lock = threading.RLock()
        self.storage = Storage()
        self._restore_rooms()
        self._stop = threading.Event()
        self._scheduler = threading.Thread(target=self._scheduler_loop, name="vault-deadline-scheduler", daemon=True)
        self._scheduler.start()

    def _restore_rooms(self):
        restored = 0
        for snap in self.storage.load_rooms():
            try:
                code = str(snap.get("code", "")).strip().upper()
                if not code: continue
                room = GameRoom(self.cfg, self.questions, code, str(snap.get("name", "")), self.storage, restored=snap)
                if room.phase == "finished" and not room.archived_at:
                    room.archived_at = datetime.now().isoformat(timespec="seconds")
                    room._persist()
                self.rooms[code] = room; restored += 1
            except Exception as e:
                print(f"[STORAGE] failed restoring room: {e}")
        if restored:
            print(f"[STORAGE] restored {restored} room(s) from {self.storage.kind}")

    def _scheduler_loop(self):
        while not self._stop.wait(0.1):
            with self.lock:
                rooms = list(self.rooms.values())
            for room in rooms:
                try:
                    room.tick(); room.flush_dirty()
                except Exception as e: print(f"[SCHEDULER] {room.code}: {e}")

    def shutdown(self):
        self._stop.set()
        with self.lock:
            rooms = list(self.rooms.values())
        for room in rooms:
            try: room.flush_dirty(force=True)
            except Exception as e: print(f"[STORAGE] final flush failed for {room.code}: {e}")

    def new_code(self):
        with self.lock:
            for _ in range(1000):
                code = "".join(secrets.choice(self.ALPHABET) for _ in range(4))
                if code not in self.rooms: return code
            raise RuntimeError("Unable to generate room code")
    def create_room(self, name: str, owner_user_id: str = ""):
        with self.lock:
            code = self.new_code(); room = GameRoom(self.cfg, self.questions, code, name, self.storage, owner_user_id=owner_user_id); self.rooms[code] = room
            with room.lock:
                room._changed(team=True, admin=True, display=True)
            return room
    def get(self, code: str): return self.rooms.get(str(code).strip().upper())
    def claim_unowned_rooms(self, owner_user_id: str):
        claimed=0
        with self.lock:
            rooms=list(self.rooms.values())
        for r in rooms:
            with r.lock:
                if not r.owner_user_id:
                    r.owner_user_id=str(owner_user_id); r._persist(); claimed+=1
        return claimed
    def can_access(self, user: dict | None, room: GameRoom | None) -> bool:
        if not user or not room or user.get("status") != "approved": return False
        return user.get("role") == "super_admin" or (room.owner_user_id and room.owner_user_id == user.get("id"))
    def list_rooms(self, user: dict | None = None):
        with self.lock:
            rooms=sorted(self.rooms.values(), key=lambda x:x.created_at, reverse=True)
        if user:
            rooms=[r for r in rooms if self.can_access(user,r)]
        return [{"code":r.code,"name":r.name,"phase":r.phase,"phase_ar":r.phase_ar(),"joins_open":r.joins_open,"team_count":len(r.teams),"created_at":r.created_at,"archived_at":r.archived_at,"is_archived":bool(r.archived_at or r.phase=="finished"),"leaderboard":r.leaderboard(10)} for r in rooms]


CONFIG, QUESTIONS = load_data()
MANAGER = RoomManager(CONFIG, QUESTIONS)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "VaultWeb/0.40"
    def log_message(self, fmt, *args): print(f"[{datetime.now():%H:%M:%S}] {self.client_address[0]} - {fmt % args}")
    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _send(self, status, body, ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(status); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store, no-cache, must-revalidate"); self._security_headers()
        if extra:
            for k,v in extra.items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)

    def _sse(self, room: GameRoom, channel: str, state_fn):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self._security_headers()
        self.end_headers()
        last = -1
        try:
            # EventSource reconnects automatically. Rotate the connection periodically so proxies do not keep stale sockets forever.
            until = time.time() + 300
            while time.time() < until:
                rev = room._revision(channel)
                if rev != last:
                    payload = json.dumps(state_fn(), ensure_ascii=False, separators=(",", ":"))
                    self.wfile.write(("event: state\ndata: " + payload + "\n\n").encode("utf-8")); self.wfile.flush(); last = rev
                new_rev = room.wait_revision(channel, last, timeout=12.0)
                if new_rev == last:
                    self.wfile.write(b": ping\n\n"); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        self.close_connection = True
    def _json(self, status, obj, extra=None): self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", extra)
    def _read_json(self):
        try:
            n=int(self.headers.get("Content-Length","0")); return json.loads((self.rfile.read(n) if n else b"{}").decode("utf-8"))
        except Exception: return {}
    def _page(self, name, replacements=None):
        text=(WEB/name).read_text(encoding="utf-8")
        for k,v in (replacements or {}).items(): text=text.replace(k, html.escape(str(v)))
        self._send(200,text.encode("utf-8"),"text/html; charset=utf-8")
    def _room_from(self, u, payload=None):
        payload = payload or {}; qs = parse_qs(u.query); code = str(payload.get("code") or qs.get("code", [""])[0]).strip().upper(); return MANAGER.get(code), code
    def _cookie_token(self):
        raw=self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" not in part: continue
            k,v=part.strip().split("=",1)
            if k == "vault_session": return v
        return ""
    def _current_user(self):
        return MANAGER.storage.get_user_by_session(self._cookie_token())
    def _set_session_cookie(self, token: str):
        secure = self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        cookie = f"vault_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"
        if secure: cookie += "; Secure"
        return cookie
    def _clear_session_cookie(self):
        secure = self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        cookie = "vault_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        if secure: cookie += "; Secure"
        return cookie
    def _admin_auth(self, room, u, payload=None):
        if not room: return False
        user=self._current_user()
        if MANAGER.can_access(user, room): return True
        if not MANAGER.storage.superadmin_exists():
            payload=payload or {}; qs=parse_qs(u.query); token=str(payload.get("admin_token") or qs.get("token",[""])[0])
            return bool(token and secrets.compare_digest(room.admin_token, token))
        return False
    def _team_auth(self, room, u, payload=None):
        if not room: return None
        payload=payload or {}; qs=parse_qs(u.query); token=str(payload.get("team_token") or qs.get("token",[""])[0]); return room.validate_team_token(token)
    def _master_pin_ok(self, payload=None, u=None):
        payload=payload or {}; qs=parse_qs(u.query) if u else {}; pin=str(payload.get("pin") or qs.get("pin",[""])[0] or self.headers.get("X-Admin-Pin", "")); return secrets.compare_digest(pin, str(CONFIG["admin_pin"]))
    def _require_user(self):
        user=self._current_user()
        return user if user and user.get("status")=="approved" else None
    def _require_superadmin(self):
        user=self._require_user()
        return user if user and user.get("role")=="super_admin" else None

    def do_GET(self):
        u=urlparse(self.path); path=u.path
        if path=="/": return self._page("index.html", {"__VERSION__":VERSION})
        if path=="/admin": return self._page("admin_home.html", {"__VERSION__":VERSION})
        if path=="/archive": return self._page("archive.html", {"__VERSION__":VERSION})
        if path=="/brand.svg":
            body=(WEB/"brand.svg").read_bytes(); return self._send(200,body,"image/svg+xml; charset=utf-8")
        if path=="/team": return self._page("team.html", {"__VERSION__":VERSION})
        if path=="/room-admin": return self._page("admin_room.html", {"__VERSION__":VERSION})
        if path=="/display": return self._page("display.html", {"__VERSION__":VERSION})
        if path=="/api/health":
            db=MANAGER.storage.health(); return self._json(200 if db.get("ok") else 503,{"ok":bool(db.get("ok")),"version":VERSION,"rooms":len(MANAGER.rooms),"database":db,"realtime":"sse","admin_pin_is_default":str(CONFIG["admin_pin"])=="2468"})
        if path=="/api/auth/status":
            user=self._current_user(); needs_setup=not MANAGER.storage.superadmin_exists()
            return self._json(200,{"ok":True,"needs_setup":needs_setup,"logged_in":bool(user),"user":public_user(user)})
        if path=="/api/admin/users":
            user=self._require_superadmin()
            if not user: return self._json(403,{"ok":False,"message":"هذه الصلاحية للمسؤول الرئيسي فقط."})
            users=MANAGER.storage.list_admin_users(); pending=sum(1 for x in users if x.get("status")=="pending")
            return self._json(200,{"ok":True,"users":users,"pending_count":pending})
        if path=="/api/team/stream":
            room,_=self._room_from(u); team=self._team_auth(room,u)
            if not room: return self._json(404,{"ok":False,"message":"الغرفة غير موجودة."})
            if not team: return self._json(403,{"ok":False,"message":"جلسة الفريق غير صالحة."})
            return self._sse(room,"team",lambda:room.team_state(team))
        if path=="/api/admin/stream":
            room,_=self._room_from(u)
            if not self._admin_auth(room,u): return self._json(403,{"ok":False,"message":"رابط المشرف غير صالح."})
            return self._sse(room,"admin",room.admin_state)
        if path=="/api/display_stream":
            room,_=self._room_from(u)
            if not room: return self._json(404,{"ok":False,"message":"الغرفة غير موجودة."})
            return self._sse(room,"display",room.display_state)
        if path=="/api/room/public":
            room,_=self._room_from(u)
            return self._json(200, room.public_summary()) if room else self._json(404,{"ok":False,"message":"رمز الغرفة غير صحيح."})
        if path=="/api/team/state":
            room,_=self._room_from(u); team=self._team_auth(room,u)
            if not room: return self._json(404,{"ok":False,"message":"الغرفة غير موجودة."})
            if not team: return self._json(403,{"ok":False,"message":"جلسة الفريق غير صالحة."})
            return self._json(200,room.team_state(team))
        if path=="/api/admin/room_state":
            room,_=self._room_from(u)
            if not self._admin_auth(room,u): return self._json(403,{"ok":False,"message":"رابط المشرف غير صالح."})
            return self._json(200,room.admin_state())
        if path=="/api/display_state":
            room,_=self._room_from(u)
            if not room: return self._json(404,{"ok":False,"message":"الغرفة غير موجودة."})
            return self._json(200,room.display_state())
        if path=="/api/admin/rooms":
            user=self._require_user()
            if not user: return self._json(401,{"ok":False,"message":"سجّل الدخول أولًا."})
            return self._json(200,{"ok":True,"rooms":MANAGER.list_rooms(user),"user":public_user(user)})
        if path=="/api/admin/archive":
            user=self._require_user(); room,_=self._room_from(u)
            if not user: return self._json(401,{"ok":False,"message":"سجّل الدخول أولًا."})
            if not MANAGER.can_access(user,room): return self._json(403,{"ok":False,"message":"لا تملك صلاحية لهذه الغرفة."})
            return self._json(200,{"ok":True,"room":room.admin_state(),"log_header":room.LOG_HEADER,"log_rows":room.log_rows[1:]})
        if path in {"/api/admin/log.xlsx","/api/admin/archive.xlsx"}:
            room,_=self._room_from(u)
            if not self._admin_auth(room,u): return self._json(403,{"ok":False,"message":"لا تملك صلاحية لهذه الغرفة."})
            body=build_event_xlsx(room.log_rows); name=f"Vault_{room.code}_Log_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
            return self._send(200,body,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", {"Content-Disposition":f'attachment; filename="{name}"'})
        return self._send(404,b"Not found")

    def do_POST(self):
        u=urlparse(self.path); path=u.path; p=self._read_json()
        if path=="/api/auth/setup":
            if MANAGER.storage.superadmin_exists(): return self._json(409,{"ok":False,"message":"تم إنشاء المسؤول الرئيسي مسبقًا."})
            if not self._master_pin_ok(p,u): return self._json(403,{"ok":False,"message":"رمز الإدارة الحالي غير صحيح."})
            email=normalize_email(p.get("email","")); name=" ".join(str(p.get("name","")).strip().split())[:120]; password=str(p.get("password", ""))
            if not EMAIL_RE.match(email): return self._json(400,{"ok":False,"message":"اكتب بريدًا إلكترونيًا صحيحًا."})
            if len(name)<2: return self._json(400,{"ok":False,"message":"اكتب اسم المسؤول."})
            if len(password)<8: return self._json(400,{"ok":False,"message":"كلمة المرور يجب أن تكون 8 أحرف على الأقل."})
            if MANAGER.storage.get_admin_user_by_email(email): return self._json(409,{"ok":False,"message":"هذا البريد مسجل مسبقًا."})
            try:
                user=MANAGER.storage.create_admin_user(email,name,hash_password(password),role="super_admin",status="approved")
                MANAGER.storage.set_admin_user_status(user["id"],"approved",approved_by=user["id"],role="super_admin")
                claimed=MANAGER.claim_unowned_rooms(user["id"])
                token=MANAGER.storage.create_admin_session(user["id"]); MANAGER.storage.touch_admin_login(user["id"])
                return self._json(200,{"ok":True,"message":"تم إنشاء حساب المسؤول الرئيسي.","user":public_user(MANAGER.storage.get_admin_user_by_id(user["id"])),"claimed_rooms":claimed}, {"Set-Cookie":self._set_session_cookie(token)})
            except sqlite3.IntegrityError:
                return self._json(409,{"ok":False,"message":"هذا البريد مسجل مسبقًا."})
            except Exception as e:
                return self._json(500,{"ok":False,"message":"تعذر إنشاء الحساب."})
        if path=="/api/auth/signup":
            if not MANAGER.storage.superadmin_exists(): return self._json(409,{"ok":False,"message":"يجب تهيئة حساب المسؤول الرئيسي أولًا."})
            email=normalize_email(p.get("email","")); name=" ".join(str(p.get("name","")).strip().split())[:120]; password=str(p.get("password", ""))
            if not EMAIL_RE.match(email): return self._json(400,{"ok":False,"message":"اكتب بريدًا إلكترونيًا صحيحًا."})
            if len(name)<2: return self._json(400,{"ok":False,"message":"اكتب اسم المشرف."})
            if len(password)<8: return self._json(400,{"ok":False,"message":"كلمة المرور يجب أن تكون 8 أحرف على الأقل."})
            if MANAGER.storage.get_admin_user_by_email(email): return self._json(409,{"ok":False,"message":"هذا البريد مسجل مسبقًا."})
            try:
                user=MANAGER.storage.create_admin_user(email,name,hash_password(password),role="supervisor",status="pending")
                return self._json(200,{"ok":True,"message":"تم إنشاء الحساب وهو بانتظار اعتماد المسؤول الرئيسي.","user":public_user(user)})
            except Exception:
                return self._json(500,{"ok":False,"message":"تعذر إنشاء الحساب."})
        if path=="/api/auth/login":
            email=normalize_email(p.get("email","")); password=str(p.get("password", "")); user=MANAGER.storage.get_admin_user_by_email(email)
            if not user or not verify_password(password,user.get("password_hash","")): return self._json(403,{"ok":False,"message":"البريد أو كلمة المرور غير صحيحة."})
            if user.get("status")=="pending": return self._json(403,{"ok":False,"message":"حسابك بانتظار اعتماد المسؤول الرئيسي."})
            if user.get("status")!="approved": return self._json(403,{"ok":False,"message":"هذا الحساب غير مفعل."})
            token=MANAGER.storage.create_admin_session(user["id"]); MANAGER.storage.touch_admin_login(user["id"]); user=MANAGER.storage.get_admin_user_by_id(user["id"])
            return self._json(200,{"ok":True,"message":"تم تسجيل الدخول.","user":public_user(user)}, {"Set-Cookie":self._set_session_cookie(token)})
        if path=="/api/auth/logout":
            MANAGER.storage.delete_admin_session(self._cookie_token())
            return self._json(200,{"ok":True,"message":"تم تسجيل الخروج."}, {"Set-Cookie":self._clear_session_cookie()})
        if path.startswith("/api/admin/users/"):
            admin=self._require_superadmin()
            if not admin: return self._json(403,{"ok":False,"message":"هذه الصلاحية للمسؤول الرئيسي فقط."})
            target_id=str(p.get("user_id", "")); target=MANAGER.storage.get_admin_user_by_id(target_id)
            if not target: return self._json(404,{"ok":False,"message":"الحساب غير موجود."})
            if target.get("role")=="super_admin" and target.get("id")==admin.get("id"): return self._json(409,{"ok":False,"message":"لا يمكن تغيير حالة حساب المسؤول الرئيسي من هنا."})
            if path=="/api/admin/users/approve": updated=MANAGER.storage.set_admin_user_status(target_id,"approved",approved_by=admin["id"],role="supervisor")
            elif path=="/api/admin/users/reject":
                MANAGER.storage.delete_sessions_for_user(target_id); updated=MANAGER.storage.set_admin_user_status(target_id,"rejected",approved_by=admin["id"],role="supervisor")
            elif path=="/api/admin/users/disable":
                MANAGER.storage.delete_sessions_for_user(target_id); updated=MANAGER.storage.set_admin_user_status(target_id,"disabled",approved_by=admin["id"],role="supervisor")
            else: return self._send(404,b"Not found")
            return self._json(200,{"ok":True,"user":public_user(updated)})
        if path=="/api/join":
            room=MANAGER.get(str(p.get("code","")).strip().upper())
            if not room: return self._json(404,{"ok":False,"message":"رمز الغرفة غير صحيح."})
            ok,msg,team=room.join_team(str(p.get("team_name","")), str(p.get("existing_token","")))
            data={"ok":ok,"message":msg}
            if ok and team: data.update({"room_code":room.code,"room_name":room.name,"team_id":team["id"],"team_name":team["name"],"team_token":team["token"],"team_url":f"/team?code={room.code}&token={team['token']}"})
            return self._json(200 if ok else 409,data)
        if path=="/api/admin/create_room":
            user=self._require_user()
            if not user or user.get("role") not in {"super_admin","supervisor"}: return self._json(403,{"ok":False,"message":"لا تملك صلاحية إنشاء غرفة."})
            room=MANAGER.create_room(str(p.get("room_name","")).strip() or "غرفة الخزنة", owner_user_id=user["id"])
            return self._json(200,{"ok":True,"message":"تم إنشاء الغرفة.","room":{"code":room.code,"name":room.name,"admin_url":f"/room-admin?code={room.code}","display_url":f"/display?code={room.code}"}})
        if path=="/api/admin/check_pin":
            ok=(not MANAGER.storage.superadmin_exists()) and self._master_pin_ok(p,u); return self._json(200 if ok else 403,{"ok":ok,"message":"الرمز صالح للتهيئة الأولى." if ok else "الرمز غير صالح أو تم إنشاء المسؤول الرئيسي مسبقًا."})

        room,_=self._room_from(u,p)
        if not room: return self._json(404,{"ok":False,"message":"الغرفة غير موجودة."})

        if path.startswith("/api/admin/"):
            if not self._admin_auth(room,u,p): return self._json(403,{"ok":False,"message":"رابط المشرف غير صالح."})
            if path=="/api/admin/toggle_join": ok,msg=room.set_join_open(bool(p.get("open")))
            elif path=="/api/admin/remove_team": ok,msg=room.remove_team(str(p.get("team_id","")))
            elif path=="/api/admin/start_game": ok,msg=room.start_game()
            elif path=="/api/admin/start_next": ok,msg=room.start_next()
            elif path=="/api/admin/close_question": ok,msg=room.close_question_now()
            elif path=="/api/admin/correct":
                corr=p.get("corrections")
                if not isinstance(corr,dict): return self._json(400,{"ok":False,"message":"بيانات التصحيح غير صحيحة."})
                ok,msg=room.apply_corrections(corr)
            elif path=="/api/admin/adjust": ok,msg=room.adjust_vault(str(p.get("team_id","")),str(p.get("mode","")),p.get("amount",0))
            elif path=="/api/admin/reset_round": ok,msg=room.reset_round()
            else: return self._send(404,b"Not found")
            return self._json(200 if ok else 409,{"ok":ok,"message":msg})

        team=self._team_auth(room,u,p)
        if not team: return self._json(403,{"ok":False,"message":"جلسة الفريق غير صالحة."})
        if path=="/api/team/draft": ok,msg=room.update_draft(team,p.get("draft",""),p.get("revision",0),p.get("question_token",0))
        elif path=="/api/team/answer": ok,msg=room.submit_answer(team,str(p.get("answer","")))
        elif path=="/api/team/storage": ok,msg=room.choose_storage(team)
        else: return self._send(404,b"Not found")
        return self._json(200 if ok else 409,{"ok":ok,"message":msg})


def local_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close(); return ip
    except Exception: return "127.0.0.1"


def main():
    port=CONFIG["port"]; ip=local_ip(); server=ThreadingHTTPServer(("0.0.0.0",port),Handler); server.daemon_threads=True
    print("="*72); print(f"{VERSION} — Persistent DB + SSE realtime")
    print(f"Participant: http://127.0.0.1:{port}/")
    print(f"Admin:       http://127.0.0.1:{port}/admin")
    print(f"LAN:         http://{ip}:{port}/")
    print(f"Database:    {MANAGER.storage.kind}")
    print("Admin PIN: configured via environment")
    print("="*72)
    try: server.serve_forever(poll_interval=.1)
    except KeyboardInterrupt: pass
    finally: MANAGER.shutdown(); server.server_close()

if __name__=="__main__": main()