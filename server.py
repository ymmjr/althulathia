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
import email_auth
from datetime import datetime
from itertools import combinations
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
LOG_DIR = Path(os.environ.get("VAULT_LOG_DIR", str(ROOT / "Logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
VERSION = "Vault Web v0.83"



EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
ADMIN_ROLES = {"super_admin", "assistant_admin", "supervisor"}
QUESTION_BANK_SEGMENTS = {
    "vault": "الخزنة",
    "top_ten": "أعلى عشرة",
    "qa": "سؤال وجواب",
}

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
        email_auth.init_schema(self)

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
                    cur.execute("CREATE TABLE IF NOT EXISTS question_bank (id TEXT PRIMARY KEY, segment TEXT NOT NULL, question_text TEXT NOT NULL, answer_json TEXT NOT NULL, difficulty INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL, updated_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_question_bank_segment ON question_bank(segment)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_question_bank_enabled ON question_bank(enabled)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_question_bank_difficulty ON question_bank(difficulty)")
                    cur.execute("CREATE TABLE IF NOT EXISTS festival_question_bank (id TEXT PRIMARY KEY, festival_round INTEGER NOT NULL, segment TEXT NOT NULL, question_text TEXT NOT NULL, answer_json TEXT NOT NULL, difficulty INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL, updated_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_festival_question_round ON festival_question_bank(festival_round)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_festival_question_segment ON festival_question_bank(segment)")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_festival_question_enabled ON festival_question_bank(enabled)")
                    cur.execute("CREATE TABLE IF NOT EXISTS question_usage (owner_user_id TEXT NOT NULL, segment TEXT NOT NULL, question_id TEXT NOT NULL, room_code TEXT NOT NULL, used_at TEXT NOT NULL, PRIMARY KEY(owner_user_id,segment,question_id))")
                    cur.execute("CREATE INDEX IF NOT EXISTS idx_question_usage_owner_segment ON question_usage(owner_user_id,segment)")
                    cur.execute("DROP TABLE IF EXISTS question_packs")
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

    def set_admin_user_role(self, user_id: str, role: str) -> dict | None:
        if role not in {"assistant_admin", "supervisor"}:
            raise ValueError("Invalid admin role")
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                if self.kind == "postgres":
                    cur.execute("UPDATE admin_users SET role=%s WHERE id=%s", (role, user_id))
                else:
                    cur.execute("UPDATE admin_users SET role=? WHERE id=?", (role, user_id))
                    con.commit()
        return self.get_admin_user_by_id(user_id)

    def _question_bank_dict(self, row) -> dict | None:
        if not row:
            return None
        keys = ("id","segment","question_text","answer_json","difficulty","enabled","created_by","updated_by","created_at","updated_at")
        data = dict(zip(keys, row))
        try:
            data["answer_data"] = json.loads(data.pop("answer_json"))
        except Exception:
            data["answer_data"] = {}
            data.pop("answer_json", None)
        data["difficulty"] = int(data.get("difficulty") or 1)
        data["enabled"] = bool(data.get("enabled"))
        data["segment_label"] = QUESTION_BANK_SEGMENTS.get(data.get("segment"), data.get("segment"))
        data["scope"] = "general"
        return data

    def list_question_bank(self, segment: str = "") -> list[dict]:
        segment = str(segment or "").strip()
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                if segment:
                    if self.kind == "postgres":
                        cur.execute("SELECT id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM question_bank WHERE segment=%s ORDER BY updated_at DESC", (segment,))
                    else:
                        cur.execute("SELECT id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM question_bank WHERE segment=? ORDER BY updated_at DESC", (segment,))
                else:
                    cur.execute("SELECT id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM question_bank ORDER BY updated_at DESC")
                rows = cur.fetchall()
        return [self._question_bank_dict(row) for row in rows]

    def get_question_bank_item(self, question_id: str) -> dict | None:
        row = self._fetchone(
            "SELECT id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM question_bank WHERE id=%s",
            "SELECT id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM question_bank WHERE id=?",
            (str(question_id),),
        )
        return self._question_bank_dict(row)

    def create_question_bank_item(self, segment: str, question_text: str, answer_data: dict, difficulty: int, enabled: bool, user_id: str) -> dict:
        question_id = uuid.uuid4().hex
        now = datetime.now().isoformat(timespec="seconds")
        answer_json = json.dumps(answer_data, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                values = (question_id, segment, question_text, answer_json, int(difficulty), 1 if enabled else 0, user_id, user_id, now, now)
                if self.kind == "postgres":
                    cur.execute("INSERT INTO question_bank(id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", values)
                else:
                    cur.execute("INSERT INTO question_bank(id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)", values)
                    con.commit()
        return self.get_question_bank_item(question_id)

    def update_question_bank_item(self, question_id: str, segment: str, question_text: str, answer_data: dict, difficulty: int, enabled: bool, user_id: str) -> dict | None:
        now = datetime.now().isoformat(timespec="seconds")
        answer_json = json.dumps(answer_data, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                values = (segment, question_text, answer_json, int(difficulty), 1 if enabled else 0, user_id, now, str(question_id))
                if self.kind == "postgres":
                    cur.execute("UPDATE question_bank SET segment=%s,question_text=%s,answer_json=%s,difficulty=%s,enabled=%s,updated_by=%s,updated_at=%s WHERE id=%s", values)
                else:
                    cur.execute("UPDATE question_bank SET segment=?,question_text=?,answer_json=?,difficulty=?,enabled=?,updated_by=?,updated_at=? WHERE id=?", values)
                    con.commit()
                if cur.rowcount <= 0:
                    return None
        return self.get_question_bank_item(question_id)

    def set_question_bank_enabled(self, question_id: str, enabled: bool, user_id: str) -> dict | None:
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                values = (1 if enabled else 0, user_id, now, str(question_id))
                if self.kind == "postgres":
                    cur.execute("UPDATE question_bank SET enabled=%s,updated_by=%s,updated_at=%s WHERE id=%s", values)
                else:
                    cur.execute("UPDATE question_bank SET enabled=?,updated_by=?,updated_at=? WHERE id=?", values)
                    con.commit()
                if cur.rowcount <= 0:
                    return None
        return self.get_question_bank_item(question_id)

    def delete_question_bank_item(self, question_id: str) -> bool:
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                if self.kind == "postgres":
                    cur.execute("DELETE FROM question_bank WHERE id=%s", (str(question_id),))
                else:
                    cur.execute("DELETE FROM question_bank WHERE id=?", (str(question_id),))
                    con.commit()
                return cur.rowcount > 0

    def _festival_question_dict(self, row) -> dict | None:
        if not row:
            return None
        keys=("id","festival_round","segment","question_text","answer_json","difficulty","enabled","created_by","updated_by","created_at","updated_at")
        data=dict(zip(keys,row))
        try:
            data["answer_data"]=json.loads(data.pop("answer_json"))
        except Exception:
            data["answer_data"]={}
            data.pop("answer_json",None)
        data["festival_round"]=int(data.get("festival_round") or 0)
        data["difficulty"]=int(data.get("difficulty") or 1)
        data["enabled"]=bool(data.get("enabled"))
        data["segment_label"]=QUESTION_BANK_SEGMENTS.get(data.get("segment"),data.get("segment"))
        data["scope"]="festival"
        return data

    def list_festival_question_bank(self, festival_round: int = 0, segment: str = "") -> list[dict]:
        festival_round=int(festival_round or 0)
        segment=str(segment or "").strip()
        where=[]; params=[]
        if festival_round>0:
            where.append("festival_round="+("%s" if self.kind=="postgres" else "?")); params.append(festival_round)
        if segment:
            where.append("segment="+("%s" if self.kind=="postgres" else "?")); params.append(segment)
        sql="SELECT id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM festival_question_bank"
        if where: sql+=" WHERE "+" AND ".join(where)
        sql+=" ORDER BY festival_round ASC, updated_at DESC"
        with self._lock:
            with self._connect() as con:
                cur=con.cursor(); cur.execute(sql,tuple(params)); rows=cur.fetchall()
        return [self._festival_question_dict(r) for r in rows]

    def get_festival_question_bank_item(self, question_id: str) -> dict | None:
        row=self._fetchone(
            "SELECT id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM festival_question_bank WHERE id=%s",
            "SELECT id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at FROM festival_question_bank WHERE id=?",
            (str(question_id),),
        )
        return self._festival_question_dict(row)

    def create_festival_question_bank_item(self, festival_round: int, segment: str, question_text: str, answer_data: dict, difficulty: int, enabled: bool, user_id: str) -> dict:
        question_id=uuid.uuid4().hex; now=datetime.now().isoformat(timespec="seconds")
        answer_json=json.dumps(answer_data,ensure_ascii=False,separators=(",",":"))
        values=(question_id,int(festival_round),segment,question_text,answer_json,int(difficulty),1 if enabled else 0,user_id,user_id,now,now)
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind=="postgres":
                    cur.execute("INSERT INTO festival_question_bank(id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",values)
                else:
                    cur.execute("INSERT INTO festival_question_bank(id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",values); con.commit()
        return self.get_festival_question_bank_item(question_id)

    def update_festival_question_bank_item(self, question_id: str, festival_round: int, segment: str, question_text: str, answer_data: dict, difficulty: int, enabled: bool, user_id: str) -> dict | None:
        now=datetime.now().isoformat(timespec="seconds")
        answer_json=json.dumps(answer_data,ensure_ascii=False,separators=(",",":"))
        values=(int(festival_round),segment,question_text,answer_json,int(difficulty),1 if enabled else 0,user_id,now,str(question_id))
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind=="postgres":
                    cur.execute("UPDATE festival_question_bank SET festival_round=%s,segment=%s,question_text=%s,answer_json=%s,difficulty=%s,enabled=%s,updated_by=%s,updated_at=%s WHERE id=%s",values)
                else:
                    cur.execute("UPDATE festival_question_bank SET festival_round=?,segment=?,question_text=?,answer_json=?,difficulty=?,enabled=?,updated_by=?,updated_at=? WHERE id=?",values); con.commit()
                if cur.rowcount<=0: return None
        return self.get_festival_question_bank_item(question_id)

    def set_festival_question_bank_enabled(self, question_id: str, enabled: bool, user_id: str) -> dict | None:
        now=datetime.now().isoformat(timespec="seconds"); values=(1 if enabled else 0,user_id,now,str(question_id))
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind=="postgres":
                    cur.execute("UPDATE festival_question_bank SET enabled=%s,updated_by=%s,updated_at=%s WHERE id=%s",values)
                else:
                    cur.execute("UPDATE festival_question_bank SET enabled=?,updated_by=?,updated_at=? WHERE id=?",values); con.commit()
                if cur.rowcount<=0: return None
        return self.get_festival_question_bank_item(question_id)

    def delete_festival_question_bank_item(self, question_id: str) -> bool:
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if self.kind=="postgres": cur.execute("DELETE FROM festival_question_bank WHERE id=%s",(str(question_id),))
                else: cur.execute("DELETE FROM festival_question_bank WHERE id=?",(str(question_id),)); con.commit()
                return cur.rowcount>0

    def question_text_exists(self, scope: str, segment: str, question_text: str, exclude_id: str = "") -> bool:
        norm=normalize_answer(question_text)
        items=self.list_festival_question_bank() if scope=="festival" else self.list_question_bank()
        return any(x.get("segment")==segment and x.get("id")!=exclude_id and normalize_answer(x.get("question_text",""))==norm for x in items)

    def festival_rounds_status(self) -> list[dict]:
        items=self.list_festival_question_bank()
        rounds={}
        for item in items:
            r=int(item.get("festival_round") or 0)
            if r<=0: continue
            entry=rounds.setdefault(r,{"round":r,"total":0,"enabled":0,"segments":{"vault":0,"top_ten":0,"qa":0},"vault_by_difficulty":{"1":0,"2":0,"3":0}})
            entry["total"]+=1
            if item.get("enabled"):
                entry["enabled"]+=1
                if item.get("segment") in entry["segments"]: entry["segments"][item["segment"]]+=1
                if item.get("segment")=="vault" and int(item.get("difficulty") or 0) in {1,2,3}:
                    entry["vault_by_difficulty"][str(int(item["difficulty"]))]+=1
        result=[]
        for r in sorted(rounds):
            e=rounds[r]; c=e["vault_by_difficulty"]
            e["vault_ready"]=c["1"]>=6 and c["2"]>=4 and c["3"]>=2
            result.append(e)
        return result

    def festival_vault_questions(self, festival_round: int) -> tuple[bool,str,list[dict]]:
        festival_round=int(festival_round or 0)
        if festival_round<=0: return False,"حدد جولة المهرجان لهذه الغرفة أولًا.",[]
        items=self.list_festival_question_bank(festival_round,"vault")
        groups={1:[],2:[],3:[]}
        for item in items:
            d=int(item.get("difficulty") or 0)
            if item.get("enabled") and d in groups: groups[d].append(item)
        need={1:6,2:4,3:2}
        missing={d:max(0,need[d]-len(groups[d])) for d in need}
        if any(missing.values()):
            parts=[f"{missing[d]} من المستوى {d}" for d in (1,2,3) if missing[d]]
            return False,f"جولة المهرجان {festival_round} غير مكتملة للخزنة؛ أضف "+" و".join(parts)+".",[]
        chosen=[]
        for d in (1,2,3):
            groups[d].sort(key=lambda x:(str(x.get("created_at","")),str(x.get("id",""))))
            chosen.extend(groups[d][:need[d]])
        game=[]
        for item in chosen:
            ans=item.get("answer_data") or {}
            game.append({"bank_id":item["id"],"question":item["question_text"],"correct_answer":str(ans.get("correct_answer","")),"difficulty":int(item["difficulty"])})
        rng=random.Random(f"festival-vault-{festival_round}")
        ordered=randomized_question_order(game,rng=rng)
        for i,q in enumerate(ordered,start=1): q["number"]=i
        return True,f"تم تحميل أسئلة جولة المهرجان {festival_round}.",ordered

    def bulk_import_questions(self, items: list[dict], user_id: str) -> dict:
        existing_general={(x["segment"],normalize_answer(x["question_text"])) for x in self.list_question_bank()}
        existing_festival={(x["segment"],normalize_answer(x["question_text"])) for x in self.list_festival_question_bank()}
        inserted_general=0; inserted_festival=0; skipped=0
        now=datetime.now().isoformat(timespec="seconds")
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                for item in items:
                    key=(item["segment"],normalize_answer(item["question_text"]))
                    scope=item.get("scope","general")
                    existing=existing_festival if scope=="festival" else existing_general
                    if key in existing:
                        skipped+=1; continue
                    qid=uuid.uuid4().hex
                    answer_json=json.dumps(item["answer_data"],ensure_ascii=False,separators=(",",":"))
                    if scope=="festival":
                        vals=(qid,int(item["festival_round"]),item["segment"],item["question_text"],answer_json,int(item["difficulty"]),1,user_id,user_id,now,now)
                        if self.kind=="postgres":
                            cur.execute("INSERT INTO festival_question_bank(id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",vals)
                        else:
                            cur.execute("INSERT INTO festival_question_bank(id,festival_round,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",vals)
                        inserted_festival+=1; existing_festival.add(key)
                    else:
                        vals=(qid,item["segment"],item["question_text"],answer_json,int(item["difficulty"]),1,user_id,user_id,now,now)
                        if self.kind=="postgres":
                            cur.execute("INSERT INTO question_bank(id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",vals)
                        else:
                            cur.execute("INSERT INTO question_bank(id,segment,question_text,answer_json,difficulty,enabled,created_by,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",vals)
                        inserted_general+=1; existing_general.add(key)
                if self.kind=="sqlite": con.commit()
        return {"general":inserted_general,"festival":inserted_festival,"skipped_duplicates":skipped,"total_inserted":inserted_general+inserted_festival}

    def question_usage_status(self, owner_user_id: str, segment: str = "") -> dict:
        owner_user_id = str(owner_user_id or "")
        items = self.list_question_bank(segment)
        with self._lock:
            with self._connect() as con:
                cur=con.cursor()
                if segment:
                    if self.kind=="postgres":
                        cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=%s AND segment=%s",(owner_user_id,segment))
                    else:
                        cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=? AND segment=?",(owner_user_id,segment))
                else:
                    if self.kind=="postgres":
                        cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=%s",(owner_user_id,))
                    else:
                        cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=?",(owner_user_id,))
                used_ids={str(r[0]) for r in cur.fetchall()}
        for item in items:
            item["used_by_you"] = item["id"] in used_ids
        enabled=[x for x in items if x.get("enabled")]
        available=[x for x in enabled if not x.get("used_by_you")]
        by_diff={str(d):sum(1 for x in available if int(x.get("difficulty") or 0)==d) for d in (1,2,3)}
        used_count=sum(1 for x in items if x.get("used_by_you"))
        result={
            "items":items,
            "total":len(items),
            "enabled":len(enabled),
            "used":used_count,
            "available":len(available),
            "available_by_difficulty":by_diff,
        }
        if segment in {"","vault"}:
            vault_items=[x for x in (items if segment=="vault" else self.list_question_bank("vault"))]
            if segment!="vault":
                with self._lock:
                    with self._connect() as con:
                        cur=con.cursor()
                        if self.kind=="postgres":
                            cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=%s AND segment=%s",(owner_user_id,"vault"))
                        else:
                            cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=? AND segment=?",(owner_user_id,"vault"))
                        vault_used={str(r[0]) for r in cur.fetchall()}
                for x in vault_items: x["used_by_you"]=x["id"] in vault_used
            vault_avail=[x for x in vault_items if x.get("enabled") and not x.get("used_by_you")]
            counts={d:sum(1 for x in vault_avail if int(x.get("difficulty") or 0)==d) for d in (1,2,3)}
            result["vault_available_by_difficulty"]={str(k):v for k,v in counts.items()}
            result["vault_rounds_remaining"]=min(counts[1]//6,counts[2]//4,counts[3]//2)
        return result

    def reserve_vault_questions(self, owner_user_id: str, room_code: str) -> tuple[bool, str, list[dict]]:
        owner_user_id = str(owner_user_id or "").strip()
        if not owner_user_id:
            return False, "لا يمكن بدء الجولة قبل ربط الغرفة بحساب مسؤول.", []
        with self._lock:
            items=self.list_question_bank("vault")
            with self._connect() as con:
                cur=con.cursor()
                if self.kind=="postgres":
                    cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=%s AND segment=%s",(owner_user_id,"vault"))
                else:
                    cur.execute("SELECT question_id FROM question_usage WHERE owner_user_id=? AND segment=?",(owner_user_id,"vault"))
                used={str(r[0]) for r in cur.fetchall()}
                groups={1:[],2:[],3:[]}
                for item in items:
                    if item.get("enabled") and item["id"] not in used and int(item.get("difficulty") or 0) in groups:
                        groups[int(item["difficulty"])].append(item)
                need={1:6,2:4,3:2}
                missing={d:max(0,need[d]-len(groups[d])) for d in need}
                if any(missing.values()):
                    parts=[]
                    labels={1:"المستوى 1",2:"المستوى 2",3:"المستوى 3"}
                    for d in (1,2,3):
                        if missing[d]: parts.append(f"{missing[d]} من {labels[d]}")
                    available=f"المتاح الآن: مستوى 1 = {len(groups[1])}، مستوى 2 = {len(groups[2])}، مستوى 3 = {len(groups[3])}"
                    return False, "لا يمكن بدء الخزنة؛ أضف "+ " و".join(parts) + f". {available}.", []
                chosen=[]
                for d in (1,2,3):
                    random.shuffle(groups[d]); chosen.extend(groups[d][:need[d]])
                now=datetime.now().isoformat(timespec="seconds")
                try:
                    for item in chosen:
                        values=(owner_user_id,"vault",item["id"],str(room_code),now)
                        if self.kind=="postgres":
                            cur.execute("INSERT INTO question_usage(owner_user_id,segment,question_id,room_code,used_at) VALUES (%s,%s,%s,%s,%s)",values)
                        else:
                            cur.execute("INSERT INTO question_usage(owner_user_id,segment,question_id,room_code,used_at) VALUES (?,?,?,?,?)",values)
                    if self.kind=="sqlite": con.commit()
                except Exception:
                    if self.kind=="sqlite": con.rollback()
                    raise
        game_questions=[]
        for item in chosen:
            answer=item.get("answer_data") or {}
            game_questions.append({
                "bank_id":item["id"],
                "question":item["question_text"],
                "correct_answer":str(answer.get("correct_answer","")),
                "difficulty":int(item["difficulty"]),
            })
        ordered=randomized_question_order(game_questions)
        for i,q in enumerate(ordered,start=1): q["number"]=i
        return True, "تم حجز 12 سؤالًا جديدًا من بنك الأسئلة.", ordered

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

    def delete_admin_user(self, user_id: str) -> bool:
        user_id = str(user_id or "")
        if not user_id:
            return False
        with self._lock:
            with self._connect() as con:
                cur = con.cursor()
                if self.kind == "postgres":
                    cur.execute("DELETE FROM admin_sessions WHERE user_id=%s", (user_id,))
                    cur.execute("DELETE FROM admin_email_otps WHERE user_id=%s", (user_id,))
                    cur.execute("DELETE FROM admin_email_verified WHERE user_id=%s", (user_id,))
                    cur.execute("DELETE FROM admin_password_resets WHERE user_id=%s", (user_id,))
                    cur.execute("DELETE FROM admin_users WHERE id=%s", (user_id,))
                    deleted = cur.rowcount > 0
                else:
                    cur.execute("DELETE FROM admin_sessions WHERE user_id=?", (user_id,))
                    cur.execute("DELETE FROM admin_email_otps WHERE user_id=?", (user_id,))
                    cur.execute("DELETE FROM admin_email_verified WHERE user_id=?", (user_id,))
                    cur.execute("DELETE FROM admin_password_resets WHERE user_id=?", (user_id,))
                    cur.execute("DELETE FROM admin_users WHERE id=?", (user_id,))
                    deleted = cur.rowcount > 0
                    con.commit()
        return deleted

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



def load_config() -> dict:
    config = {
        "game_title": "الخزنة",
        "question_seconds": 15,
        "storage_seconds": 5,
        "port": 8080,
        "max_multiplier": 128,
        "admin_pin": os.environ.get("VAULT_ADMIN_PIN", "2468"),
    }
    config["port"] = int(os.environ.get("PORT", os.environ.get("VAULT_PORT", config["port"])))
    config["question_seconds"] = int(os.environ.get("VAULT_QUESTION_SECONDS", config["question_seconds"]))
    config["storage_seconds"] = int(os.environ.get("VAULT_STORAGE_SECONDS", config["storage_seconds"]))
    config["max_multiplier"] = max(1, int(os.environ.get("VAULT_MAX_MULTIPLIER", config["max_multiplier"])))
    return config


def randomized_question_order(questions: list[dict], rng=None) -> list[dict]:
    rng = rng or random
    items = [dict(q) for q in questions]
    hard = [q for q in items if q.get("difficulty") == 3]
    other = [q for q in items if q.get("difficulty") != 3]
    n = len(items)
    allowed_positions = list(range(1, n - 1))
    valid_positions = [p for p in combinations(allowed_positions, len(hard)) if all((b - a) > 1 for a, b in zip(p, p[1:]))]
    if not valid_positions:
        raise ValueError("Cannot place hard questions with current constraints")
    chosen = set(rng.choice(valid_positions))
    rng.shuffle(hard); rng.shuffle(other)
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


def build_question_import_template_xlsx() -> bytes:
    from io import BytesIO
    from xml.sax.saxutils import escape
    sheets=[
        ("الخزنة",["نوع البنك","رقم الجولة","مستوى الصعوبة","السؤال","الإجابة الصحيحة"]),
        ("أعلى عشرة",["نوع البنك","رقم الجولة","مستوى الصعوبة","السؤال"]+[f"المرتبة {i}" for i in range(1,11)]),
        ("سؤال وجواب",["نوع البنك","رقم الجولة","مستوى الصعوبة","السؤال","الإجابة الصحيحة"]),
    ]
    content_types=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">','<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>','<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    for i in range(1,4): content_types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append("</Types>")
    workbook='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+''.join(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>' for i,(name,_) in enumerate(sheets,1))+'</sheets></workbook>'
    wb_rels=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i in range(1,4): wb_rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>')
    wb_rels.append('<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    root_rels='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    styles='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Arial"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1066AB"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf></cellXfs></styleSheet>'''
    bio=BytesIO()
    with zipfile.ZipFile(bio,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml","".join(content_types)); z.writestr("_rels/.rels",root_rels); z.writestr("xl/workbook.xml",workbook); z.writestr("xl/_rels/workbook.xml.rels","".join(wb_rels)); z.writestr("xl/styles.xml",styles)
        for idx,(name,headers) in enumerate(sheets,1):
            last=excel_col(len(headers))
            cells=''.join(f'<c r="{excel_col(i+1)}1" t="inlineStr" s="1"><is><t>{escape(h)}</t></is></c>' for i,h in enumerate(headers))
            widths=[]
            for col in range(1,len(headers)+1):
                w=14 if col==1 else 13 if col==2 else 16 if col==3 else 42 if col==4 else 22
                widths.append(f'<col min="{col}" max="{col}" width="{w}" customWidth="1"/>')
            validation='<dataValidations count="2"><dataValidation type="list" allowBlank="1" sqref="A2:A1000"><formula1>&quot;عام,مهرجان&quot;</formula1></dataValidation><dataValidation type="list" allowBlank="1" sqref="C2:C1000"><formula1>&quot;1,2,3&quot;</formula1></dataValidation></dataValidations>'
            sheet=f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView rightToLeft="1" workbookViewId="0"/></sheetViews><cols>{''.join(widths)}</cols><sheetData><row r="1" ht="28" customHeight="1">{cells}</row></sheetData><autoFilter ref="A1:{last}1000"/>{validation}</worksheet>'''
            z.writestr(f"xl/worksheets/sheet{idx}.xml",sheet)
    return bio.getvalue()


def _decode_question_import_file(payload: dict) -> bytes:
    raw=str(payload.get("file_base64","") or "")
    if raw.startswith("data:") and "," in raw: raw=raw.split(",",1)[1]
    if not raw: raise ValueError("اختر ملف Excel أولًا.")
    if len(raw)>16_000_000: raise ValueError("حجم الملف كبير جدًا.")
    try: data=base64.b64decode(raw,validate=True)
    except Exception: raise ValueError("تعذر قراءة ملف Excel.")
    if len(data)>10_000_000: raise ValueError("حجم الملف يتجاوز الحد المسموح.")
    return data


def parse_question_import_xlsx(data: bytes) -> tuple[list[dict],list[dict]]:
    from io import BytesIO
    from xml.etree import ElementTree as ET
    import posixpath
    main_ns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel_ns="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg_rel_ns="http://schemas.openxmlformats.org/package/2006/relationships"
    items=[]; errors=[]
    def col_index(ref):
        letters="".join(ch for ch in str(ref) if ch.isalpha()).upper(); n=0
        for ch in letters: n=n*26+(ord(ch)-64)
        return max(0,n-1)
    def norm_sheet(name):
        return normalize_answer(str(name)).replace("أ","ا").replace("إ","ا").replace("آ","ا")
    recognized={"الخزنة":"vault","اعلى عشرة":"top_ten","سؤال وجواب":"qa"}
    try:
        with zipfile.ZipFile(BytesIO(data),"r") as z:
            total=sum(x.file_size for x in z.infolist())
            if total>60_000_000: raise ValueError("ملف Excel غير مقبول لأن حجمه الداخلي كبير جدًا.")
            names=set(z.namelist())
            if "xl/workbook.xml" not in names or "xl/_rels/workbook.xml.rels" not in names: raise ValueError("ملف Excel غير صالح.")
            shared=[]
            if "xl/sharedStrings.xml" in names:
                root=ET.fromstring(z.read("xl/sharedStrings.xml"))
                for si in root.findall(f"{{{main_ns}}}si"):
                    shared.append("".join(t.text or "" for t in si.iter(f"{{{main_ns}}}t")))
            relroot=ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
            relmap={r.attrib.get("Id"):r.attrib.get("Target","") for r in relroot.findall(f"{{{pkg_rel_ns}}}Relationship")}
            wb=ET.fromstring(z.read("xl/workbook.xml"))
            found=0; total_rows=0
            for sh in wb.findall(f".//{{{main_ns}}}sheet"):
                sheet_name=str(sh.attrib.get("name",""))
                segment=recognized.get(norm_sheet(sheet_name))
                if not segment: continue
                found+=1
                rid=sh.attrib.get(f"{{{rel_ns}}}id"); target=relmap.get(rid,"")
                if not target: errors.append({"sheet":sheet_name,"row":1,"message":"تعذر قراءة ورقة العمل."}); continue
                path=target.lstrip("/")
                if not path.startswith("xl/"): path=posixpath.normpath("xl/"+path)
                if path not in names: errors.append({"sheet":sheet_name,"row":1,"message":"ملف ورقة العمل غير موجود."}); continue
                root=ET.fromstring(z.read(path)); rows=[]
                for row in root.findall(f".//{{{main_ns}}}row"):
                    rnum=int(row.attrib.get("r") or (len(rows)+1)); vals={}
                    for cell in row.findall(f"{{{main_ns}}}c"):
                        idx=col_index(cell.attrib.get("r","")); typ=cell.attrib.get("t","")
                        val=""
                        if typ=="inlineStr":
                            val="".join(t.text or "" for t in cell.iter(f"{{{main_ns}}}t"))
                        else:
                            ve=cell.find(f"{{{main_ns}}}v"); raw=ve.text if ve is not None and ve.text is not None else ""
                            if typ=="s" and raw:
                                try: val=shared[int(raw)]
                                except Exception: val=""
                            else: val=raw
                        vals[idx]=str(val).strip()
                    rows.append((rnum,vals))
                if not rows: errors.append({"sheet":sheet_name,"row":1,"message":"الورقة فارغة."}); continue
                header_row=next(((rn,v) for rn,v in rows if any(str(x).strip() for x in v.values())),None)
                if not header_row: continue
                hr,header_vals=header_row
                header={str(v).strip():i for i,v in header_vals.items() if str(v).strip()}
                required=["نوع البنك","رقم الجولة","مستوى الصعوبة","السؤال"]
                required += [f"المرتبة {i}" for i in range(1,11)] if segment=="top_ten" else ["الإجابة الصحيحة"]
                missing=[x for x in required if x not in header]
                if missing:
                    errors.append({"sheet":sheet_name,"row":hr,"message":"أعمدة ناقصة: "+"، ".join(missing)}); continue
                for rnum,vals in rows:
                    if rnum<=hr: continue
                    get=lambda key: str(vals.get(header[key],"") or "").strip()
                    raw_values=[get(x) for x in required]
                    if not any(raw_values): continue
                    total_rows+=1
                    if total_rows>10000: raise ValueError("الملف يحتوي على عدد أسئلة أكبر من الحد المسموح.")
                    bank_raw=normalize_answer(get("نوع البنك")).replace("أ","ا").replace("إ","ا")
                    if bank_raw in {"عام","العامة","general"}: scope="general"
                    elif bank_raw in {"مهرجان","مهرجان خاص","خاص","festival"}: scope="festival"
                    else:
                        errors.append({"sheet":sheet_name,"row":rnum,"message":"نوع البنك يجب أن يكون «عام» أو «مهرجان»."}); continue
                    try:
                        diff=int(float(get("مستوى الصعوبة")))
                    except Exception:
                        diff=0
                    round_no=0
                    if scope=="festival":
                        try: round_no=int(float(get("رقم الجولة")))
                        except Exception: round_no=0
                        if round_no<=0:
                            errors.append({"sheet":sheet_name,"row":rnum,"message":"أسئلة المهرجان تحتاج رقم جولة صحيحًا."}); continue
                    body={"scope":scope,"festival_round":round_no,"segment":segment,"question":get("السؤال"),"difficulty":diff,"enabled":True}
                    if segment=="top_ten": body["answers"]=[get(f"المرتبة {i}") for i in range(1,11)]
                    else: body["correct_answer"]=get("الإجابة الصحيحة")
                    try:
                        normalized=normalize_question_bank_payload(body)
                        normalized["source_sheet"]=sheet_name; normalized["source_row"]=rnum
                        items.append(normalized)
                    except ValueError as e:
                        errors.append({"sheet":sheet_name,"row":rnum,"message":str(e)})
            if found==0: errors.append({"sheet":"—","row":1,"message":"لم يتم العثور على أوراق «الخزنة» أو «أعلى عشرة» أو «سؤال وجواب»."})
    except zipfile.BadZipFile:
        raise ValueError("الملف ليس ملف Excel بصيغة xlsx صالحًا.")
    return items,errors


def analyze_question_import(data: bytes, storage: Storage) -> dict:
    items,errors=parse_question_import_xlsx(data)
    existing_general={(x["segment"],normalize_answer(x["question_text"])) for x in storage.list_question_bank()}
    existing_festival={(x["segment"],normalize_answer(x["question_text"])) for x in storage.list_festival_question_bank()}
    seen=set(); duplicates=[]; importable=[]
    for item in items:
        key=(item["scope"],item["segment"],normalize_answer(item["question_text"]))
        exists=(item["segment"],normalize_answer(item["question_text"])) in (existing_festival if item["scope"]=="festival" else existing_general)
        if key in seen or exists:
            duplicates.append({"sheet":item.get("source_sheet",""),"row":item.get("source_row",0),"question":item["question_text"],"scope":item["scope"],"segment":item["segment"]})
            continue
        seen.add(key); importable.append(item)
    by_scope={"general":0,"festival":0}; by_segment={"vault":0,"top_ten":0,"qa":0}; rounds={}
    for item in importable:
        by_scope[item["scope"]]+=1; by_segment[item["segment"]]+=1
        if item["scope"]=="festival":
            r=str(item["festival_round"]); rounds[r]=rounds.get(r,0)+1
    return {
        "importable":importable,
        "errors":errors,
        "duplicates":duplicates,
        "summary":{"valid":len(importable),"errors":len(errors),"duplicates":len(duplicates),"by_scope":by_scope,"by_segment":by_segment,"festival_rounds":rounds},
    }


def normalize_name(s: str) -> str:
    return " ".join(str(s).strip().split()).casefold()


def normalize_answer(s: str) -> str:
    return " ".join(str(s).strip().split()).casefold()


def normalize_question_bank_payload(payload) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("بيانات السؤال غير صحيحة.")
    scope = str(payload.get("scope", "general")).strip().lower()
    if scope not in {"general","festival"}:
        raise ValueError("نوع البنك غير صحيح.")
    try:
        festival_round = int(payload.get("festival_round", 0) or 0)
    except Exception:
        festival_round = 0
    if scope=="festival" and festival_round<=0:
        raise ValueError("حدد رقم جولة المهرجان.")
    segment = str(payload.get("segment", "")).strip()
    if segment not in QUESTION_BANK_SEGMENTS:
        raise ValueError("اختر فقرة صحيحة.")
    question_text = " ".join(str(payload.get("question", "")).strip().split())
    if not question_text:
        raise ValueError("اكتب نص السؤال.")
    if len(question_text) > 1200:
        raise ValueError("نص السؤال طويل جدًا.")
    try:
        difficulty = int(payload.get("difficulty", 1))
    except Exception:
        difficulty = 0
    if difficulty not in {1, 2, 3}:
        raise ValueError("مستوى الصعوبة يجب أن يكون من 1 إلى 3.")
    enabled = bool(payload.get("enabled", True))
    if segment in {"vault", "qa"}:
        correct_answer = " ".join(str(payload.get("correct_answer", "")).strip().split())
        if not correct_answer:
            raise ValueError("اكتب الإجابة الصحيحة.")
        if len(correct_answer) > 1200:
            raise ValueError("الإجابة الصحيحة طويلة جدًا.")
        answer_data = {"correct_answer": correct_answer}
    else:
        answers = payload.get("answers")
        if not isinstance(answers, list) or len(answers) != 10:
            raise ValueError("فقرة أعلى عشرة تحتاج إلى 10 إجابات مرتبة.")
        cleaned = [" ".join(str(x or "").strip().split()) for x in answers]
        if any(not x for x in cleaned):
            raise ValueError("أكمل الإجابات العشر كلها.")
        if any(len(x) > 500 for x in cleaned):
            raise ValueError("إحدى إجابات أعلى عشرة طويلة جدًا.")
        normalized = [normalize_answer(x) for x in cleaned]
        if len(set(normalized)) != 10:
            raise ValueError("إجابات أعلى عشرة يجب أن تكون مختلفة عن بعضها.")
        answer_data = {"answers": cleaned}
    return {
        "scope": scope,
        "festival_round": festival_round,
        "segment": segment,
        "question_text": question_text,
        "answer_data": answer_data,
        "difficulty": difficulty,
        "enabled": enabled,
    }


class GameRoom:
    LOG_HEADER = ["الوقت", "رقم الحدث", "رمز الغرفة", "رقم السؤال", "الفريق", "الحدث", "القيمة", "الخزنة قبل", "الخزنة بعد", "المعرض للخطر قبل", "المعرض للخطر بعد", "قيمة السؤال قبل", "قيمة السؤال بعد", "الإجابة", "التصحيح", "القرار", "ملاحظة"]
    EVENT_AR = {
        "ROOM_CREATED":"إنشاء الغرفة", "TEAM_JOINED":"انضمام فريق", "TEAM_REMOVED":"إزالة فريق", "JOIN_OPENED":"فتح الانضمام", "JOIN_CLOSED":"إغلاق الانضمام",
        "GAME_STARTED":"بدء الفقرة", "QUESTION_STARTED":"بدء السؤال", "ANSWER_SUBMITTED":"إرسال إجابة", "QUESTION_TIME_ENDED":"انتهاء وقت السؤال", "QUESTION_TIME_ENDED_MANUALLY":"إنهاء وقت السؤال يدويًا",
        "CORRECTION":"تصحيح الإجابة", "STORAGE_WINDOW_STARTED":"بدء مهلة التخزين", "STORAGE_BUTTON_PRESSED":"اختيار التخزين", "STORED":"تخزين النقاط", "RISK_CONTINUES":"استمرار المخاطرة",
        "QUESTION_RESOLVED":"اعتماد نتيجة السؤال", "MANUAL_ADD":"إضافة يدوية للخزنة", "MANUAL_DEDUCT":"خصم يدوي من الخزنة", "ROUND_RESET":"إعادة تهيئة الجولة", "GAME_FINISHED":"انتهاء الفقرة", "ROOM_CLOSED":"إغلاق الغرفة", "ROOM_REOPENED":"إعادة فتح الغرفة"
    }

    def __init__(self, config: dict, questions: list[dict], code: str, name: str, storage: Storage, restored: dict | None = None, owner_user_id: str = "", owner_name: str = "", owner_email: str = "", room_type: str = "normal", festival_round: int = 0, question_pack_id: str = "", question_pack_label: str = "", question_pack_version: int = 0):
        self.cfg = dict(config)
        self.base_questions = [dict(q) for q in questions]
        self.storage = storage
        self.code = code
        self.name = name.strip() or f"غرفة {code}"
        self.admin_token = secrets.token_urlsafe(18)
        self.created_at = datetime.now().isoformat(timespec="seconds")
        self.owner_user_id = str(owner_user_id or "")
        self.owner_name = str(owner_name or "")[:120]
        self.owner_email = normalize_email(owner_email)
        self.room_type = "private" if room_type == "private" else "normal"
        self.festival_round = int(festival_round or 0)
        self.question_pack_id = str(question_pack_id or "")
        self.question_pack_label = str(question_pack_label or "")[:120]
        self.question_pack_version = int(question_pack_version or 0)
        self.archived_at = None
        self.closed_at = None
        self.closed_joins_open = False
        self.paused_question_remaining_ms = 0
        self.paused_storage_remaining_ms = 0
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
        self.owner_name = str(d.get("owner_name") or self.owner_name or "")[:120]
        self.owner_email = normalize_email(d.get("owner_email") or self.owner_email or "")
        self.room_type = "private" if d.get("room_type") == "private" else "normal"
        self.festival_round = int(d.get("festival_round", self.festival_round) or 0)
        self.question_pack_id = str(d.get("question_pack_id") or self.question_pack_id or "")
        self.question_pack_label = str(d.get("question_pack_label") or self.question_pack_label or "")[:120]
        self.question_pack_version = int(d.get("question_pack_version", self.question_pack_version) or 0)
        self.archived_at = d.get("archived_at")
        self.closed_at = d.get("closed_at")
        self.closed_joins_open = bool(d.get("closed_joins_open", False))
        self.paused_question_remaining_ms = int(d.get("paused_question_remaining_ms", 0) or 0)
        self.paused_storage_remaining_ms = int(d.get("paused_storage_remaining_ms", 0) or 0)
        self.questions = [dict(q) for q in d.get("questions", self.base_questions)]
        if self.room_type == "private":
            self.base_questions = [dict(q) for q in self.questions]
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
            "schema": 5, "code": self.code, "name": self.name, "admin_token": self.admin_token, "created_at": self.created_at, "owner_user_id": self.owner_user_id, "owner_name": self.owner_name, "owner_email": self.owner_email, "room_type": self.room_type, "festival_round": self.festival_round, "question_pack_id": self.question_pack_id, "question_pack_label": self.question_pack_label, "question_pack_version": self.question_pack_version, "archived_at": self.archived_at, "closed_at": self.closed_at,
            "closed_joins_open": self.closed_joins_open, "paused_question_remaining_ms": self.paused_question_remaining_ms, "paused_storage_remaining_ms": self.paused_storage_remaining_ms,
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
        self.questions = []
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
            if self.closed_at:
                return False, "هذه الغرفة مغلقة وتم نقلها إلى السجل.", None
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
            self._event("SYSTEM", "ROUND_RESET", note="إعادة جميع الفرق إلى الانتظار وتصفير الجولة")
            self._changed(team=True, admin=True, display=True)
            return True, "تمت إعادة تهيئة الجولة وفتح الانضمام."

    def start_game(self):
        with self.lock:
            if self.game_started: return False, "الجولة بدأت بالفعل."
            if not self.teams: return False, "لا يوجد أي فريق داخل الغرفة."
            if self.room_type=="private":
                ok,msg,questions=self.storage.festival_vault_questions(self.festival_round)
            else:
                ok,msg,questions=self.storage.reserve_vault_questions(self.owner_user_id,self.code)
            if not ok:
                return False,msg
            self.questions=questions
            self.joins_open = False
            self.game_started = True
            self.phase = "ready"
            self._event("SYSTEM", "JOIN_CLOSED", note="إغلاق تلقائي عند بدء الجولة")
            self._event("SYSTEM", "GAME_STARTED", value=len(self.teams), note=("بدأت فقرة الخزنة من بنك المهرجان الخاص" if self.room_type=="private" else "بدأت فقرة الخزنة من البنك العام؛ تم حجز 12 سؤالًا غير مستخدم لهذا الحساب"))
            self._changed(team=True,admin=True,display=True)
            return self.start_next()

    def _finalize_unsubmitted_from_drafts(self):
        for t in self.teams.values():
            if t["submitted"]: continue
            final = t["draft"].strip()[:500]
            t["answer"] = final
            t["auto_finalized"] = bool(final)

    def tick(self):
        with self.lock:
            if self.closed_at:
                return
            now = self._now_ms()
            if self.phase == "question_open" and now >= self.question_deadline_ms:
                self.closed_question_deadline_ms = self.question_deadline_ms
                self._finalize_unsubmitted_from_drafts()
                self.phase = "waiting_correction"
                self.question_deadline_ms = 0
                self.correction_ready_ms = self.closed_question_deadline_ms + 400
                self._event("SYSTEM", "QUESTION_TIME_ENDED", note="انتهى الوقت واعتمد آخر مسودة لغير المرسلين")
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
            self._event("SYSTEM", "QUESTION_TIME_ENDED_MANUALLY", note="أنهى المشرف وقت الإجابة واعتمد آخر مسودة")
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

    def close_room(self):
        with self.lock:
            if self.closed_at:
                return False, "الغرفة مغلقة بالفعل."
            now_ms = self._now_ms()
            self.closed_joins_open = bool(self.joins_open)
            self.paused_question_remaining_ms = max(0, self.question_deadline_ms - now_ms) if self.phase == "question_open" else 0
            self.paused_storage_remaining_ms = max(0, self.storage_deadline_ms - now_ms) if self.phase == "storage_open" else 0
            self.question_deadline_ms = 0
            self.storage_deadline_ms = 0
            self.joins_open = False
            self.closed_at = datetime.now().isoformat(timespec="seconds")
            self._event("SYSTEM", "ROOM_CLOSED", note="أغلق المشرف الغرفة إداريًا ونقلها إلى السجل")
            self._changed(team=True, admin=True, display=True)
            return True, "تم إغلاق الغرفة ونقلها إلى السجل."

    def reopen_room(self):
        with self.lock:
            if not self.closed_at:
                return False, "الغرفة ليست مغلقة."
            now_ms = self._now_ms()
            self.closed_at = None
            if self.phase == "question_open" and self.paused_question_remaining_ms > 0:
                self.question_deadline_ms = now_ms + self.paused_question_remaining_ms
            if self.phase == "storage_open" and self.paused_storage_remaining_ms > 0:
                self.storage_deadline_ms = now_ms + self.paused_storage_remaining_ms
            if self.phase == "lobby" and not self.game_started:
                self.joins_open = bool(self.closed_joins_open)
            self.paused_question_remaining_ms = 0
            self.paused_storage_remaining_ms = 0
            self.closed_joins_open = False
            self._event("SYSTEM", "ROOM_REOPENED", note="أعاد المسؤول الرئيسي فتح الغرفة")
            self._changed(team=True, admin=True, display=True)
            return True, "تمت إعادة فتح الغرفة."

    def phase_ar(self):
        if self.closed_at:
            return "الغرفة مغلقة"
        return {"lobby":"بانتظار الفرق", "ready":"جاهز", "question_open":"وقت الإجابة", "waiting_correction":"بانتظار التصحيح", "storage_open":"وقت التخزين", "resolved":"تم اعتماد النتيجة", "finished":"انتهت الفقرة"}.get(self.phase, self.phase)

    def team_status(self, t: dict):
        if self.closed_at: return "الغرفة مغلقة"
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
            return {"ok": True, "code": self.code, "name": self.name, "phase": self.phase, "phase_ar": self.phase_ar(), "joins_open": self.joins_open, "game_started": self.game_started, "team_count": len(self.teams), "room_closed": bool(self.closed_at), "closed_at": self.closed_at}

    def team_state(self, team: dict):
        with self.lock:
            self.tick(); now = self._now_ms(); q = self.current_question()
            team["last_seen_ms"] = now
            return {
                "room_code": self.code, "room_name": self.name, "phase": self.phase, "phase_ar": self.phase_ar(), "joins_open": self.joins_open, "room_closed": bool(self.closed_at), "closed_at": self.closed_at,
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
                "room_code":self.code, "room_name":self.name, "created_at":self.created_at, "archived_at":self.archived_at, "closed_at":self.closed_at, "room_closed":bool(self.closed_at), "owner_user_id":self.owner_user_id, "owner_name":self.owner_name, "owner_email":self.owner_email, "room_type":self.room_type, "question_pack_id":self.question_pack_id, "question_pack_label":self.question_pack_label, "question_pack_version":self.question_pack_version, "phase":self.phase, "phase_ar":self.phase_ar(), "joins_open":self.joins_open, "game_started":self.game_started,
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
            if self.closed_at:
                headline = "الغرفة مغلقة"
                timer = 0; subline = "تم نقل الغرفة إلى السجل"
            elif self.phase == "question_open":
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
            return {"room_code":self.code, "room_name":self.name, "phase":self.phase, "phase_ar":self.phase_ar(), "room_closed":bool(self.closed_at), "closed_at":self.closed_at, "server_now_ms":now, "question_deadline_ms":self.question_deadline_ms, "storage_deadline_ms":self.storage_deadline_ms, "question_no":self.index+1 if self.index>=0 else 0, "total_questions":len(self.questions), "headline":headline, "subline":subline, "timer":timer, "team_count":total, "submitted_count":submitted, "leaderboard":self.leaderboard(10)}


class RoomManager:
    ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    def __init__(self, config):
        self.cfg = config; self.rooms: dict[str, GameRoom] = {}; self.lock = threading.RLock()
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
                room = GameRoom(self.cfg, [], code, str(snap.get("name", "")), self.storage, restored=snap)
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
    def create_room(self, name: str, owner_user_id: str = "", owner_name: str = "", owner_email: str = "", room_type: str = "normal", festival_round: int = 0):
        with self.lock:
            room_type = "private" if room_type == "private" else "normal"
            code = self.new_code()
            room = GameRoom(
                self.cfg, [], code, name, self.storage,
                owner_user_id=owner_user_id, owner_name=owner_name, owner_email=owner_email,
                room_type=room_type, festival_round=festival_round,
            )
            self.rooms[code] = room
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
        if not user or not room or user.get("status") != "approved":
            return False
        role = user.get("role")
        if room.room_type == "private":
            return role in {"super_admin", "assistant_admin"}
        return role == "super_admin" or (room.owner_user_id and room.owner_user_id == user.get("id"))
    def preserve_owner_identity(self, user: dict) -> int:
        changed = 0
        user_id = str(user.get("id") or "")
        if not user_id:
            return 0
        with self.lock:
            rooms = list(self.rooms.values())
        for room in rooms:
            with room.lock:
                if room.owner_user_id == user_id:
                    room.owner_name = room.owner_name or str(user.get("name") or "")[:120]
                    room.owner_email = room.owner_email or normalize_email(user.get("email") or "")
                    room._persist()
                    changed += 1
        return changed
    def list_rooms(self, user: dict | None = None):
        with self.lock:
            rooms=sorted(self.rooms.values(), key=lambda x:x.created_at, reverse=True)
        if user:
            rooms=[r for r in rooms if self.can_access(user,r)]
        return [{"code":r.code,"name":r.name,"phase":r.phase,"phase_ar":r.phase_ar(),"joins_open":r.joins_open,"team_count":len(r.teams),"created_at":r.created_at,"archived_at":r.archived_at,"closed_at":r.closed_at,"is_closed":bool(r.closed_at),"is_archived":bool(r.closed_at or r.archived_at or r.phase=="finished"),"owner_user_id":r.owner_user_id,"owner_name":r.owner_name,"owner_email":r.owner_email,"room_type":r.room_type,"is_private":r.room_type=="private","festival_round":r.festival_round,"question_pack_id":r.question_pack_id,"question_pack_label":r.question_pack_label,"question_pack_version":r.question_pack_version,"leaderboard":r.leaderboard(10)} for r in rooms]


CONFIG = load_config()
MANAGER = RoomManager(CONFIG)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "VaultWeb/0.83"
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
    def _public_base_url(self):
        configured = os.environ.get("APP_BASE_URL", "").strip().rstrip("/")
        if configured:
            return configured
        proto = self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip() or "http"
        host = self.headers.get("Host", f"127.0.0.1:{CONFIG['port']}").strip()
        return f"{proto}://{host}"
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
    def _require_content_admin(self):
        user=self._require_user()
        return user if user and user.get("role") in {"super_admin","assistant_admin"} else None

    def do_GET(self):
        u=urlparse(self.path); path=u.path
        if path=="/": return self._page("index.html", {"__VERSION__":VERSION})
        if path=="/admin": return self._page("admin_home.html", {"__VERSION__":VERSION})
        if path in {"/admin/dashboard","/admin/rooms","/admin/questions","/admin/accounts","/admin/archive","/admin/settings"}: return self._page("admin_portal.html", {"__VERSION__":VERSION})
        if path in {"/archive","/admin/archive/room"}: return self._page("archive.html", {"__VERSION__":VERSION})
        if path=="/brand.svg":
            body=(WEB/"brand.svg").read_bytes(); return self._send(200,body,"image/svg+xml; charset=utf-8")
        if path=="/brand.webp":
            body=(WEB/"brand.webp").read_bytes(); return self._send(200,body,"image/webp")
        if path=="/team": return self._page("team.html", {"__VERSION__":VERSION})
        if path in {"/room-admin","/admin/room"}: return self._page("admin_room.html", {"__VERSION__":VERSION})
        if path=="/display": return self._page("display.html", {"__VERSION__":VERSION})
        if path=="/api/health":
            db=MANAGER.storage.health(); return self._json(200 if db.get("ok") else 503,{"ok":bool(db.get("ok")),"version":VERSION,"rooms":len(MANAGER.rooms),"database":db,"realtime":"sse","admin_pin_is_default":str(CONFIG["admin_pin"])=="2468"})
        if path=="/api/auth/status":
            user=self._current_user(); needs_setup=not MANAGER.storage.superadmin_exists()
            return self._json(200,{"ok":True,"needs_setup":needs_setup,"logged_in":bool(user),"user":public_user(user),"email_auth":email_auth.status_payload()})
        if path=="/api/system/email-test":
            qs=parse_qs(u.query); supplied=str(qs.get("token",[""])[0]); expected=os.environ.get("EMAIL_TEST_SECRET","")
            if not expected or not supplied or not secrets.compare_digest(supplied,expected): return self._send(404,b"Not found")
            to_email=normalize_email(os.environ.get("EMAIL_TEST_TO",""))
            if not EMAIL_RE.match(to_email): return self._json(503,{"ok":False,"message":"Test destination is not configured."})
            try:
                result=email_auth.send_test_email(to_email)
                return self._json(200,{"ok":True,"provider":email_auth.delivery_provider(),"result":result})
            except Exception as e:
                print(f"[EMAIL] self-test failed: {e}")
                return self._json(502,{"ok":False,"provider":email_auth.delivery_provider(),"message":str(e)[:600]})
        if path=="/api/admin/users":
            user=self._require_superadmin()
            if not user: return self._json(403,{"ok":False,"message":"هذه الصلاحية للمسؤول الرئيسي فقط."})
            users=MANAGER.storage.list_admin_users()
            for x in users:
                x["email_verified"]=email_auth.is_verified(MANAGER.storage,x)
            pending=sum(1 for x in users if x.get("status")=="pending" and x.get("email_verified"))
            return self._json(200,{"ok":True,"users":users,"pending_count":pending})
        if path=="/api/admin/questions/template.xlsx":
            user=self._require_content_admin()
            if not user: return self._json(403,{"ok":False,"message":"بنك الأسئلة متاح للمسؤول الرئيسي والمسؤول المساعد فقط."})
            body=build_question_import_template_xlsx()
            return self._send(200,body,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",{"Content-Disposition":'attachment; filename="althulathia_questions_template.xlsx"'})
        if path=="/api/admin/festival-rounds":
            user=self._require_content_admin()
            if not user: return self._json(403,{"ok":False,"message":"غير مصرح."})
            return self._json(200,{"ok":True,"rounds":MANAGER.storage.festival_rounds_status()})
        if path=="/api/admin/questions":
            user=self._require_content_admin()
            if not user:
                return self._json(403,{"ok":False,"message":"بنك الأسئلة متاح للمسؤول الرئيسي والمسؤول المساعد فقط."})
            qs=parse_qs(u.query)
            scope=str(qs.get("scope",["general"])[0]).strip().lower()
            segment=str(qs.get("segment",[""])[0]).strip()
            try: festival_round=int(qs.get("round",["0"])[0] or 0)
            except Exception: festival_round=0
            if scope not in {"general","festival"}:
                return self._json(400,{"ok":False,"message":"نوع البنك غير صحيح."})
            if segment and segment not in QUESTION_BANK_SEGMENTS:
                return self._json(400,{"ok":False,"message":"الفقرة المطلوبة غير صحيحة."})
            if scope=="festival":
                items=MANAGER.storage.list_festival_question_bank(festival_round,segment)
                rounds=MANAGER.storage.festival_rounds_status()
                return self._json(200,{"ok":True,"scope":"festival","items":items,"rounds":rounds,"segments":QUESTION_BANK_SEGMENTS})
            usage=MANAGER.storage.question_usage_status(user["id"],segment)
            items=usage.pop("items")
            return self._json(200,{"ok":True,"scope":"general","items":items,"usage":usage,"segments":QUESTION_BANK_SEGMENTS})
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
            if not room:
                return self._json(404,{"ok":False,"message":"رمز الغرفة غير صحيح."})
            data=room.public_summary()
            data["join_url"]=f"{self._public_base_url()}/?code={room.code}"
            return self._json(200,data)
        if path=="/api/room/qr":
            room,_=self._room_from(u)
            if not room:
                return self._json(404,{"ok":False,"message":"رمز الغرفة غير صحيح."})
            try:
                import io
                import qrcode
                import qrcode.image.svg
                target=f"{self._public_base_url()}/?code={room.code}"
                qr=qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=10,
                    border=2,
                )
                qr.add_data(target)
                qr.make(fit=True)
                img=qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
                buf=io.BytesIO()
                img.save(buf)
                return self._send(200,buf.getvalue(),"image/svg+xml; charset=utf-8")
            except Exception as e:
                print(f"[QR] generation failed for {room.code}: {e}")
                return self._json(500,{"ok":False,"message":"تعذر إنشاء رمز الدخول."})
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
            existing=MANAGER.storage.get_admin_user_by_email(email)
            if existing:
                if email_auth.enabled() and existing.get("status") in {"email_unverified","pending"} and not email_auth.is_verified(MANAGER.storage,existing):
                    return self._json(409,{"ok":False,"message":"هذا البريد مسجل ولم يتم تأكيده بعد. أدخل رمز التحقق أو اطلب رمزًا جديدًا.","requires_verification":True,"email":email})
                return self._json(409,{"ok":False,"message":"هذا البريد مسجل مسبقًا."})
            if email_auth.enabled() and not email_auth.configured():
                return self._json(503,{"ok":False,"message":"خدمة البريد غير جاهزة حاليًا. تواصل مع الدعم الفني."})
            try:
                status="email_unverified" if email_auth.enabled() else "pending"
                user=MANAGER.storage.create_admin_user(email,name,hash_password(password),role="supervisor",status=status)
                if email_auth.enabled():
                    try:
                        delivery=email_auth.issue_otp(MANAGER.storage,user)
                        return self._json(200,{"ok":True,"message":"تم إرسال رمز تحقق إلى بريدك الإلكتروني.","user":public_user(user),"requires_verification":True,"email":email,"otp_expires_in":delivery.get("expires_in",600),"resend_after":delivery.get("resend_after",60)})
                    except Exception as e:
                        print(f"[EMAIL] OTP send failed for {email}: {e}")
                        return self._json(503,{"ok":False,"message":"تم إنشاء الحساب لكن تعذر إرسال رمز التحقق. جرّب إعادة الإرسال بعد قليل.","requires_verification":True,"email":email})
                return self._json(200,{"ok":True,"message":"تم إنشاء الحساب وهو بانتظار اعتماد المسؤول الرئيسي.","user":public_user(user)})
            except Exception as e:
                print(f"[AUTH] signup failed: {e}")
                return self._json(500,{"ok":False,"message":"تعذر إنشاء الحساب."})
        if path=="/api/auth/verify-email":
            if not email_auth.enabled(): return self._json(409,{"ok":False,"message":"تأكيد البريد غير مفعّل."})
            email=normalize_email(p.get("email","")); code=str(p.get("code","")).strip()
            if not EMAIL_RE.match(email) or not re.fullmatch(r"\d{6}",code):
                return self._json(400,{"ok":False,"message":"أدخل البريد ورمز التحقق المكوّن من 6 أرقام."})
            try:
                ok,msg,user=email_auth.verify_otp(MANAGER.storage,email,code)
                return self._json(200 if ok else 400,{"ok":ok,"message":msg,"user":public_user(user),"requires_approval":bool(ok)})
            except Exception as e:
                print(f"[EMAIL] verify failed for {email}: {e}")
                return self._json(500,{"ok":False,"message":"تعذر التحقق من الرمز حاليًا."})
        if path=="/api/auth/resend-otp":
            if not email_auth.enabled(): return self._json(409,{"ok":False,"message":"تأكيد البريد غير مفعّل."})
            email=normalize_email(p.get("email",""))
            if not EMAIL_RE.match(email): return self._json(400,{"ok":False,"message":"اكتب بريدًا إلكترونيًا صحيحًا."})
            try:
                ok,msg,extra=email_auth.resend_otp(MANAGER.storage,email)
                return self._json(200 if ok else 429,{"ok":ok,"message":msg,**extra})
            except Exception as e:
                print(f"[EMAIL] resend OTP failed for {email}: {e}")
                return self._json(503,{"ok":False,"message":"تعذر إرسال الرمز حاليًا. جرّب مرة أخرى بعد قليل."})
        if path=="/api/auth/forgot-password":
            email=normalize_email(p.get("email",""))
            generic="إذا كان البريد مسجلًا لدينا فستصلك رسالة إعادة تعيين كلمة المرور."
            if email_auth.enabled() and email_auth.configured() and EMAIL_RE.match(email):
                threading.Thread(target=lambda: email_auth.request_password_reset(MANAGER.storage,email),daemon=True).start()
            return self._json(200,{"ok":True,"message":generic})
        if path=="/api/auth/reset-password":
            if not email_auth.enabled(): return self._json(409,{"ok":False,"message":"استعادة كلمة المرور غير مفعّلة."})
            token=str(p.get("token","")).strip(); password=str(p.get("password",""))
            if len(password)<8: return self._json(400,{"ok":False,"message":"كلمة المرور يجب أن تكون 8 أحرف على الأقل."})
            try:
                ok,msg=email_auth.reset_password(MANAGER.storage,token,hash_password(password))
                return self._json(200 if ok else 400,{"ok":ok,"message":msg})
            except Exception as e:
                print(f"[EMAIL] reset password failed: {e}")
                return self._json(500,{"ok":False,"message":"تعذر تحديث كلمة المرور حاليًا."})
        if path=="/api/auth/login":
            email=normalize_email(p.get("email","")); password=str(p.get("password", "")); user=MANAGER.storage.get_admin_user_by_email(email)
            if not user or not verify_password(password,user.get("password_hash","")): return self._json(403,{"ok":False,"message":"البريد أو كلمة المرور غير صحيحة."})
            if email_auth.enabled() and user.get("role")!="super_admin" and user.get("status") in {"email_unverified","pending"} and not email_auth.is_verified(MANAGER.storage,user):
                return self._json(403,{"ok":False,"message":"يجب تأكيد بريدك الإلكتروني أولًا.","requires_verification":True,"email":email})
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
            if target.get("role")=="super_admin": return self._json(409,{"ok":False,"message":"لا يمكن تعديل أو حذف حساب المسؤول الرئيسي من هنا."})
            if path=="/api/admin/users/delete":
                MANAGER.preserve_owner_identity(target)
                deleted=MANAGER.storage.delete_admin_user(target_id)
                return self._json(200 if deleted else 404,{"ok":bool(deleted),"message":"تم حذف الحساب مع الاحتفاظ بسجل الغرف السابقة." if deleted else "الحساب غير موجود."})
            if path=="/api/admin/users/set-role":
                if target.get("status")!="approved":
                    return self._json(409,{"ok":False,"message":"يجب اعتماد الحساب أولًا قبل تغيير صلاحيته."})
                role=str(p.get("role",""))
                if role not in {"assistant_admin","supervisor"}:
                    return self._json(400,{"ok":False,"message":"الصلاحية المطلوبة غير صحيحة."})
                updated=MANAGER.storage.set_admin_user_role(target_id,role)
                return self._json(200,{"ok":True,"message":"تم تحديث صلاحية الحساب.","user":public_user(updated)})
            if path=="/api/admin/users/approve":
                if email_auth.enabled() and not email_auth.is_verified(MANAGER.storage,target):
                    return self._json(409,{"ok":False,"message":"لا يمكن اعتماد الحساب قبل تأكيد البريد الإلكتروني."})
                role=target.get("role") if target.get("role") in {"assistant_admin","supervisor"} else "supervisor"
                updated=MANAGER.storage.set_admin_user_status(target_id,"approved",approved_by=admin["id"],role=role)
                if email_auth.enabled() and email_auth.configured():
                    threading.Thread(target=lambda u=updated: email_auth.send_approval_email(u),daemon=True).start()
            elif path=="/api/admin/users/reject":
                role=target.get("role") if target.get("role") in {"assistant_admin","supervisor"} else "supervisor"
                MANAGER.storage.delete_sessions_for_user(target_id); updated=MANAGER.storage.set_admin_user_status(target_id,"rejected",approved_by=admin["id"],role=role)
            elif path=="/api/admin/users/disable":
                role=target.get("role") if target.get("role") in {"assistant_admin","supervisor"} else "supervisor"
                MANAGER.storage.delete_sessions_for_user(target_id); updated=MANAGER.storage.set_admin_user_status(target_id,"disabled",approved_by=admin["id"],role=role)
            else: return self._send(404,b"Not found")
            return self._json(200,{"ok":True,"user":public_user(updated)})
        if path=="/api/join":
            room=MANAGER.get(str(p.get("code","")).strip().upper())
            if not room: return self._json(404,{"ok":False,"message":"رمز الغرفة غير صحيح."})
            ok,msg,team=room.join_team(str(p.get("team_name","")), str(p.get("existing_token","")))
            data={"ok":ok,"message":msg}
            if ok and team: data.update({"room_code":room.code,"room_name":room.name,"team_id":team["id"],"team_name":team["name"],"team_token":team["token"],"team_url":f"/team?code={room.code}&token={team['token']}"})
            return self._json(200 if ok else 409,data)
        if path.startswith("/api/admin/questions/"):
            user=self._require_content_admin()
            if not user:
                return self._json(403,{"ok":False,"message":"بنك الأسئلة متاح للمسؤول الرئيسي والمسؤول المساعد فقط."})
            if path in {"/api/admin/questions/import-preview","/api/admin/questions/import-commit"}:
                try:
                    data=_decode_question_import_file(p)
                    analysis=analyze_question_import(data,MANAGER.storage)
                    summary=analysis["summary"]
                    if path=="/api/admin/questions/import-preview":
                        return self._json(200,{"ok":True,"message":"تم فحص الملف.","summary":summary,"errors":analysis["errors"][:100],"duplicates":analysis["duplicates"][:100]})
                    if analysis["errors"]:
                        return self._json(400,{"ok":False,"message":"لا يمكن الاستيراد قبل تصحيح أخطاء الملف.","summary":summary,"errors":analysis["errors"][:100]})
                    result=MANAGER.storage.bulk_import_questions(analysis["importable"],user["id"])
                    return self._json(200,{"ok":True,"message":f"تم استيراد {result['total_inserted']} سؤالًا بنجاح.","result":result,"summary":summary})
                except ValueError as e:
                    return self._json(400,{"ok":False,"message":str(e)})
                except Exception as e:
                    print(f"[QUESTION_IMPORT] failed: {e}")
                    return self._json(500,{"ok":False,"message":"تعذر معالجة ملف Excel."})
            scope=str(p.get("scope","general")).strip().lower()
            if scope not in {"general","festival"}:
                return self._json(400,{"ok":False,"message":"نوع البنك غير صحيح."})
            if path=="/api/admin/questions/create":
                try:
                    data=normalize_question_bank_payload(p)
                    if MANAGER.storage.question_text_exists(data["scope"],data["segment"],data["question_text"]):
                        return self._json(409,{"ok":False,"message":"هذا السؤال موجود مسبقًا في نفس البنك."})
                    if data["scope"]=="festival":
                        item=MANAGER.storage.create_festival_question_bank_item(data["festival_round"],data["segment"],data["question_text"],data["answer_data"],data["difficulty"],data["enabled"],user["id"])
                    else:
                        item=MANAGER.storage.create_question_bank_item(data["segment"],data["question_text"],data["answer_data"],data["difficulty"],data["enabled"],user["id"])
                    return self._json(200,{"ok":True,"message":"تمت إضافة السؤال.","item":item})
                except ValueError as e:
                    return self._json(400,{"ok":False,"message":str(e)})
                except Exception as e:
                    print(f"[QUESTION_BANK] create failed: {e}")
                    return self._json(500,{"ok":False,"message":"تعذر حفظ السؤال."})
            question_id=str(p.get("question_id","")).strip()
            current=MANAGER.storage.get_festival_question_bank_item(question_id) if scope=="festival" else MANAGER.storage.get_question_bank_item(question_id)
            if not current:
                return self._json(404,{"ok":False,"message":"السؤال غير موجود."})
            if path=="/api/admin/questions/update":
                try:
                    data=normalize_question_bank_payload(p)
                    if MANAGER.storage.question_text_exists(data["scope"],data["segment"],data["question_text"],exclude_id=question_id):
                        return self._json(409,{"ok":False,"message":"يوجد سؤال آخر بنفس النص في هذا البنك."})
                    if scope=="festival":
                        item=MANAGER.storage.update_festival_question_bank_item(question_id,data["festival_round"],data["segment"],data["question_text"],data["answer_data"],data["difficulty"],data["enabled"],user["id"])
                    else:
                        item=MANAGER.storage.update_question_bank_item(question_id,data["segment"],data["question_text"],data["answer_data"],data["difficulty"],data["enabled"],user["id"])
                    return self._json(200,{"ok":True,"message":"تم تحديث السؤال.","item":item})
                except ValueError as e:
                    return self._json(400,{"ok":False,"message":str(e)})
                except Exception as e:
                    print(f"[QUESTION_BANK] update failed for {question_id}: {e}")
                    return self._json(500,{"ok":False,"message":"تعذر تحديث السؤال."})
            if path=="/api/admin/questions/toggle":
                item=MANAGER.storage.set_festival_question_bank_enabled(question_id,bool(p.get("enabled")),user["id"]) if scope=="festival" else MANAGER.storage.set_question_bank_enabled(question_id,bool(p.get("enabled")),user["id"])
                return self._json(200,{"ok":True,"message":"تم تفعيل السؤال." if item and item.get("enabled") else "تم تعطيل السؤال.","item":item})
            if path=="/api/admin/questions/delete":
                deleted=MANAGER.storage.delete_festival_question_bank_item(question_id) if scope=="festival" else MANAGER.storage.delete_question_bank_item(question_id)
                return self._json(200 if deleted else 404,{"ok":bool(deleted),"message":"تم حذف السؤال." if deleted else "السؤال غير موجود."})
            return self._send(404,b"Not found")
        if path=="/api/admin/create_room":
            user=self._require_user()
            if not user or user.get("role") not in {"super_admin","assistant_admin","supervisor"}:
                return self._json(403,{"ok":False,"message":"لا تملك صلاحية إنشاء غرفة."})
            room_type="private" if str(p.get("room_type","normal"))=="private" else "normal"
            if room_type=="private" and user.get("role") not in {"super_admin","assistant_admin"}:
                return self._json(403,{"ok":False,"message":"إنشاء غرف المهرجان الخاصة متاح للمسؤول الرئيسي والمسؤول المساعد فقط."})
            festival_round=0
            if room_type=="private":
                try: festival_round=int(p.get("festival_round",0) or 0)
                except Exception: festival_round=0
                available={int(x["round"]) for x in MANAGER.storage.festival_rounds_status()}
                if festival_round<=0 or festival_round not in available:
                    return self._json(400,{"ok":False,"message":"اختر جولة مهرجان موجودة في بنك المهرجان."})
            room=MANAGER.create_room(
                str(p.get("room_name","")).strip() or ("غرفة مهرجان خاصة" if room_type=="private" else "غرفة الخزنة"),
                owner_user_id=user["id"], owner_name=user.get("name",""), owner_email=user.get("email",""),
                room_type=room_type, festival_round=festival_round,
            )
            return self._json(200,{"ok":True,"message":"تم إنشاء الغرفة الخاصة وربطها بجولة المهرجان." if room_type=="private" else "تم إنشاء الغرفة. سيتم حجز أسئلتها من البنك العام عند بدء الخزنة.","room":{"code":room.code,"name":room.name,"room_type":room.room_type,"festival_round":room.festival_round,"admin_url":f"/admin/room?code={room.code}","display_url":f"/display?code={room.code}"}})
        if path=="/api/admin/check_pin":
            ok=(not MANAGER.storage.superadmin_exists()) and self._master_pin_ok(p,u); return self._json(200 if ok else 403,{"ok":ok,"message":"الرمز صالح للتهيئة الأولى." if ok else "الرمز غير صالح أو تم إنشاء المسؤول الرئيسي مسبقًا."})

        room,_=self._room_from(u,p)
        if not room: return self._json(404,{"ok":False,"message":"الغرفة غير موجودة."})

        if path.startswith("/api/admin/"):
            if not self._admin_auth(room,u,p): return self._json(403,{"ok":False,"message":"رابط المشرف غير صالح."})
            if path=="/api/admin/close_room":
                ok,msg=room.close_room()
            elif path=="/api/admin/reopen_room":
                admin=self._require_superadmin()
                if not admin: return self._json(403,{"ok":False,"message":"إعادة فتح الغرفة متاحة للمسؤول الرئيسي فقط."})
                ok,msg=room.reopen_room()
            elif room.closed_at:
                return self._json(409,{"ok":False,"message":"الغرفة مغلقة. يمكن للمسؤول الرئيسي إعادة فتحها من السجل."})
            elif path=="/api/admin/toggle_join": ok,msg=room.set_join_open(bool(p.get("open")))
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

        if room.closed_at: return self._json(409,{"ok":False,"message":"هذه الغرفة مغلقة وتم نقلها إلى السجل."})
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