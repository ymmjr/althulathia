from __future__ import annotations

import hashlib
import html
import json
import os
import secrets
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from email.utils import parseaddr
from urllib.parse import quote

OTP_TTL_SECONDS = 10 * 60
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
RESET_TTL_SECONDS = 30 * 60


def enabled() -> bool:
    return os.environ.get("EMAIL_AUTH_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}


def support_email() -> str:
    return os.environ.get("SUPPORT_EMAIL", "support@playalthulathia.com").strip()


def app_base_url() -> str:
    return os.environ.get("APP_BASE_URL", "https://playalthulathia.com").strip().rstrip("/")


def _resend_api_key() -> str:
    return os.environ.get("RESEND_API_KEY", "").strip()


def _worker_url() -> str:
    return os.environ.get("EMAIL_WORKER_URL", "").strip().rstrip("/")


def _worker_secret() -> str:
    return os.environ.get("EMAIL_WORKER_SECRET", "").strip()


def _smtp_host() -> str:
    return os.environ.get("SMTP_HOST", "").strip()


def _smtp_port() -> int:
    try:
        return int(os.environ.get("SMTP_PORT", "465"))
    except Exception:
        return 465


def _smtp_username() -> str:
    return os.environ.get("SMTP_USERNAME", "").strip()


def _smtp_password() -> str:
    return os.environ.get("SMTP_PASSWORD", "").strip()


def _email_from() -> str:
    return os.environ.get("EMAIL_FROM", "الثلاثية الثقافية <no-reply@playalthulathia.com>").strip()


def _token_secret() -> str:
    return os.environ.get("EMAIL_TOKEN_SECRET", "").strip()


def delivery_provider() -> str:
    if _resend_api_key():
        return "resend"
    if _worker_url() and _worker_secret():
        return "worker"
    if _smtp_host() and _smtp_username() and _smtp_password():
        return "smtp"
    return "none"


def configured() -> bool:
    return bool(_token_secret() and _email_from() and delivery_provider() != "none")


def status_payload() -> dict:
    return {
        "enabled": enabled(),
        "configured": configured(),
        "provider": delivery_provider(),
        "support_email": support_email(),
    }


def init_schema(storage) -> None:
    with storage._lock:
        with storage._connect() as con:
            cur = con.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS admin_email_otps ("
                "user_id TEXT PRIMARY KEY, otp_hash TEXT NOT NULL, expires_at BIGINT NOT NULL, "
                "attempts INTEGER NOT NULL, resend_after BIGINT NOT NULL)"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS admin_email_verified ("
                "user_id TEXT PRIMARY KEY, verified_at TEXT NOT NULL)"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS admin_password_resets ("
                "token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, "
                "expires_at BIGINT NOT NULL, used_at BIGINT)"
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_admin_password_resets_user ON admin_password_resets(user_id)")
            if storage.kind == "sqlite":
                con.commit()


def is_verified(storage, user: dict | None) -> bool:
    if not user:
        return False
    if user.get("role") == "super_admin" or user.get("status") == "approved":
        return True
    row = storage._fetchone(
        "SELECT verified_at FROM admin_email_verified WHERE user_id=%s",
        "SELECT verified_at FROM admin_email_verified WHERE user_id=?",
        (user["id"],),
    )
    return bool(row)


def mark_verified(storage, user_id: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with storage._lock:
        with storage._connect() as con:
            cur = con.cursor()
            if storage.kind == "postgres":
                cur.execute(
                    "INSERT INTO admin_email_verified(user_id,verified_at) VALUES (%s,%s) "
                    "ON CONFLICT(user_id) DO UPDATE SET verified_at=EXCLUDED.verified_at",
                    (user_id, now),
                )
            else:
                cur.execute(
                    "INSERT INTO admin_email_verified(user_id,verified_at) VALUES (?,?) "
                    "ON CONFLICT(user_id) DO UPDATE SET verified_at=excluded.verified_at",
                    (user_id, now),
                )
                con.commit()


def _otp_hash(user_id: str, code: str) -> str:
    secret = _token_secret()
    if not secret:
        raise RuntimeError("EMAIL_TOKEN_SECRET is not configured")
    return hashlib.sha256(f"{secret}|{user_id}|{code}".encode("utf-8")).hexdigest()


def _reset_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _send_via_resend(to_email: str, subject: str, html_body: str, text_body: str) -> dict:
    payload = {
        "from": _email_from(),
        "to": [to_email],
        "subject": subject,
        "html": html_body,
    }
    if text_body:
        payload["text"] = text_body
    if support_email():
        payload["reply_to"] = support_email()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {_resend_api_key()}",
            "Content-Type": "application/json",
            "User-Agent": "Althulathia-Vault/0.42",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            raw = response.read().decode("utf-8")
            return {"provider": "resend", **json.loads(raw or "{}")}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend HTTP {exc.code}: {detail[:500]}") from exc
    except Exception as exc:
        raise RuntimeError(f"Resend delivery failed: {exc}") from exc


def _send_via_worker(to_email: str, subject: str, html_body: str, text_body: str) -> dict:
    payload = {
        "to": to_email,
        "subject": subject,
        "html": html_body,
        "text": text_body,
    }
    req = urllib.request.Request(
        _worker_url() + "/",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + _worker_secret(),
            "Content-Type": "application/json",
            "User-Agent": "Althulathia-Vault/0.43",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read().decode("utf-8")
            data = json.loads(raw or "{}")
            if not data.get("ok"):
                raise RuntimeError(f"Worker rejected delivery: {str(data)[:400]}")
            return {"provider": "worker", **data}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Worker HTTP {exc.code}: {detail[:500]}") from exc
    except Exception as exc:
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError(f"Worker delivery failed: {exc}") from exc


def _send_via_smtp(to_email: str, subject: str, html_body: str, text_body: str) -> dict:
    display_name, sender_email = parseaddr(_email_from())
    if not sender_email:
        sender_email = _email_from()
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _email_from()
    msg["To"] = to_email
    if support_email():
        msg["Reply-To"] = support_email()
    msg.set_content(text_body or "رسالة من منصة الثلاثية الثقافية.")
    msg.add_alternative(html_body, subtype="html")
    host, port = _smtp_host(), _smtp_port()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=15) as smtp:
                smtp.login(_smtp_username(), _smtp_password())
                smtp.send_message(msg, from_addr=sender_email, to_addrs=[to_email])
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(_smtp_username(), _smtp_password())
                smtp.send_message(msg, from_addr=sender_email, to_addrs=[to_email])
        return {"provider": "smtp", "accepted": True}
    except Exception as exc:
        raise RuntimeError(f"SMTP delivery failed: {exc}") from exc


def _send_email(to_email: str, subject: str, html_body: str, text_body: str = "") -> dict:
    if not configured():
        raise RuntimeError("Email delivery is not configured")
    provider = delivery_provider()
    if provider == "resend":
        return _send_via_resend(to_email, subject, html_body, text_body)
    if provider == "worker":
        return _send_via_worker(to_email, subject, html_body, text_body)
    if provider == "smtp":
        return _send_via_smtp(to_email, subject, html_body, text_body)
    raise RuntimeError("No email provider configured")


def _shell(title: str, inner: str) -> str:
    safe_title = html.escape(title)
    logo = html.escape(app_base_url() + "/brand.webp", quote=True)
    support = html.escape(support_email())
    return f"""<!doctype html>
<html lang="ar" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#F4F9FC;font-family:Tahoma,Arial,sans-serif;color:#083C61">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#F4F9FC;padding:26px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:#fff;border:1px solid #C8DDE9;border-radius:20px;overflow:hidden">
<tr><td style="padding:26px 28px 10px;text-align:center"><img src="{logo}" alt="الثلاثية الثقافية" style="max-width:260px;width:70%;height:auto"></td></tr>
<tr><td style="padding:10px 30px 30px">
<h1 style="margin:0 0 16px;color:#1066AB;font-size:27px">{safe_title}</h1>
{inner}
<hr style="border:0;border-top:1px solid #DCEAF2;margin:26px 0 16px">
<p style="margin:0;color:#638398;font-size:13px;line-height:1.8">للدعم الفني: <a href="mailto:{support}" style="color:#1066AB">{support}</a></p>
</td></tr></table></td></tr></table></body></html>"""


def send_otp_email(user: dict, code: str) -> dict:
    name = html.escape(str(user.get("name") or "المشرف"))
    code_safe = html.escape(code)
    inner = f"""
<p style="font-size:16px;line-height:1.9">مرحبًا {name}،</p>
<p style="font-size:16px;line-height:1.9">استخدم رمز التحقق التالي لتأكيد بريدك الإلكتروني:</p>
<div style="direction:ltr;text-align:center;font-size:36px;font-weight:900;letter-spacing:8px;color:#1066AB;background:#F2F8FC;border:1px solid #C8DDE9;border-radius:14px;padding:18px;margin:20px 0">{code_safe}</div>
<p style="font-size:15px;line-height:1.9;color:#638398">الرمز صالح لمدة 10 دقائق. لا تشاركه مع أي شخص.</p>
"""
    return _send_email(
        user["email"],
        "رمز تأكيد البريد — الثلاثية الثقافية",
        _shell("تأكيد البريد الإلكتروني", inner),
        f"رمز تأكيد بريدك هو: {code}. الرمز صالح لمدة 10 دقائق.",
    )


def send_pending_email(user: dict) -> dict:
    name = html.escape(str(user.get("name") or "المشرف"))
    inner = f"""
<p style="font-size:16px;line-height:1.9">مرحبًا {name}،</p>
<p style="font-size:16px;line-height:1.9">تم تأكيد بريدك الإلكتروني بنجاح.</p>
<div style="background:#FFF5EA;border:1px solid #F7C58F;border-radius:14px;padding:16px;color:#8A4D16;font-weight:700;line-height:1.9">حسابك الآن بانتظار اعتماد المسؤول الرئيسي.</div>
"""
    return _send_email(
        user["email"],
        "تم تأكيد بريدك — بانتظار الاعتماد",
        _shell("تم تأكيد بريدك الإلكتروني", inner),
        "تم تأكيد بريدك الإلكتروني. حسابك الآن بانتظار اعتماد المسؤول الرئيسي.",
    )


def send_approval_email(user: dict) -> dict:
    name = html.escape(str(user.get("name") or "المشرف"))
    login_url = html.escape(app_base_url() + "/admin", quote=True)
    inner = f"""
<p style="font-size:16px;line-height:1.9">مرحبًا {name}،</p>
<p style="font-size:16px;line-height:1.9">تم اعتماد حسابك كمشرف في منصة الثلاثية الثقافية، ويمكنك تسجيل الدخول الآن.</p>
<p style="text-align:center;margin:26px 0"><a href="{login_url}" style="display:inline-block;background:#1066AB;color:#fff;text-decoration:none;font-weight:900;padding:14px 26px;border-radius:12px">تسجيل الدخول</a></p>
"""
    return _send_email(
        user["email"],
        "تم اعتماد حسابك — الثلاثية الثقافية",
        _shell("تم اعتماد حسابك", inner),
        "تم اعتماد حسابك في منصة الثلاثية الثقافية. يمكنك تسجيل الدخول الآن: " + app_base_url() + "/admin",
    )


def send_reset_email(user: dict, token: str) -> dict:
    name = html.escape(str(user.get("name") or "المشرف"))
    reset_url = app_base_url() + "/admin?reset=" + quote(token)
    reset_safe = html.escape(reset_url, quote=True)
    inner = f"""
<p style="font-size:16px;line-height:1.9">مرحبًا {name}،</p>
<p style="font-size:16px;line-height:1.9">وصلنا طلب لإعادة تعيين كلمة المرور لحسابك.</p>
<p style="text-align:center;margin:26px 0"><a href="{reset_safe}" style="display:inline-block;background:#F58D27;color:#fff;text-decoration:none;font-weight:900;padding:14px 26px;border-radius:12px">إعادة تعيين كلمة المرور</a></p>
<p style="font-size:15px;line-height:1.9;color:#638398">الرابط صالح لمدة 30 دقيقة ويعمل مرة واحدة فقط. إذا لم تطلب تغيير كلمة المرور فتجاهل هذه الرسالة.</p>
"""
    return _send_email(
        user["email"],
        "إعادة تعيين كلمة المرور — الثلاثية الثقافية",
        _shell("إعادة تعيين كلمة المرور", inner),
        "رابط إعادة تعيين كلمة المرور صالح لمدة 30 دقيقة: " + reset_url,
    )


def issue_otp(storage, user: dict, enforce_cooldown: bool = False) -> dict:
    if not enabled():
        raise RuntimeError("Email verification is disabled")
    if not configured():
        raise RuntimeError("Email delivery is not configured")
    now = int(time.time())
    if enforce_cooldown:
        row = storage._fetchone(
            "SELECT resend_after FROM admin_email_otps WHERE user_id=%s",
            "SELECT resend_after FROM admin_email_otps WHERE user_id=?",
            (user["id"],),
        )
        if row and int(row[0]) > now:
            return {"ok": False, "message": f"يمكن إعادة إرسال الرمز بعد {int(row[0]) - now} ثانية.", "retry_after": int(row[0]) - now}
    code = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = _otp_hash(user["id"], code)
    expires = now + OTP_TTL_SECONDS
    resend_after = now + OTP_RESEND_SECONDS
    with storage._lock:
        with storage._connect() as con:
            cur = con.cursor()
            if storage.kind == "postgres":
                cur.execute(
                    "INSERT INTO admin_email_otps(user_id,otp_hash,expires_at,attempts,resend_after) VALUES (%s,%s,%s,%s,%s) "
                    "ON CONFLICT(user_id) DO UPDATE SET otp_hash=EXCLUDED.otp_hash, expires_at=EXCLUDED.expires_at, attempts=0, resend_after=EXCLUDED.resend_after",
                    (user["id"], otp_hash, expires, 0, resend_after),
                )
            else:
                cur.execute(
                    "INSERT INTO admin_email_otps(user_id,otp_hash,expires_at,attempts,resend_after) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(user_id) DO UPDATE SET otp_hash=excluded.otp_hash, expires_at=excluded.expires_at, attempts=0, resend_after=excluded.resend_after",
                    (user["id"], otp_hash, expires, 0, resend_after),
                )
                con.commit()
    result = send_otp_email(user, code)
    return {"ok": True, "expires_in": OTP_TTL_SECONDS, "resend_after": OTP_RESEND_SECONDS, "delivery": result}


def verify_otp(storage, email: str, code: str) -> tuple[bool, str, dict | None]:
    user = storage.get_admin_user_by_email(email)
    if not user:
        return False, "رمز التحقق غير صحيح أو انتهت صلاحيته.", None
    if is_verified(storage, user):
        return True, "تم تأكيد البريد مسبقًا.", user
    if user.get("status") not in {"email_unverified", "pending"}:
        return False, "هذا الحساب غير متاح للتحقق.", None
    row = storage._fetchone(
        "SELECT otp_hash,expires_at,attempts FROM admin_email_otps WHERE user_id=%s",
        "SELECT otp_hash,expires_at,attempts FROM admin_email_otps WHERE user_id=?",
        (user["id"],),
    )
    if not row:
        return False, "اطلب إرسال رمز تحقق جديد.", None
    expected, expires_at, attempts = row
    now = int(time.time())
    if int(expires_at) < now:
        return False, "انتهت صلاحية الرمز. اطلب رمزًا جديدًا.", None
    if int(attempts) >= OTP_MAX_ATTEMPTS:
        return False, "تم تجاوز عدد المحاولات. اطلب رمزًا جديدًا.", None
    supplied = _otp_hash(user["id"], str(code or "").strip())
    if not secrets.compare_digest(str(expected), supplied):
        with storage._lock:
            with storage._connect() as con:
                cur = con.cursor()
                if storage.kind == "postgres":
                    cur.execute("UPDATE admin_email_otps SET attempts=attempts+1 WHERE user_id=%s", (user["id"],))
                else:
                    cur.execute("UPDATE admin_email_otps SET attempts=attempts+1 WHERE user_id=?", (user["id"],))
                    con.commit()
        return False, "رمز التحقق غير صحيح.", None
    mark_verified(storage, user["id"])
    updated = storage.set_admin_user_status(user["id"], "pending", approved_by=None, role="supervisor")
    with storage._lock:
        with storage._connect() as con:
            cur = con.cursor()
            if storage.kind == "postgres":
                cur.execute("DELETE FROM admin_email_otps WHERE user_id=%s", (user["id"],))
            else:
                cur.execute("DELETE FROM admin_email_otps WHERE user_id=?", (user["id"],))
                con.commit()
    try:
        send_pending_email(updated)
    except Exception:
        pass
    return True, "تم تأكيد البريد. حسابك الآن بانتظار اعتماد المسؤول الرئيسي.", updated


def resend_otp(storage, email: str) -> tuple[bool, str, dict]:
    user = storage.get_admin_user_by_email(email)
    if not user or is_verified(storage, user):
        return True, "إذا كان الحساب يحتاج تأكيدًا فسيتم إرسال رمز جديد.", {}
    if user.get("status") not in {"email_unverified", "pending"}:
        return True, "إذا كان الحساب يحتاج تأكيدًا فسيتم إرسال رمز جديد.", {}
    if user.get("status") == "pending":
        user = storage.set_admin_user_status(user["id"], "email_unverified", approved_by=None, role="supervisor")
    result = issue_otp(storage, user, enforce_cooldown=True)
    if not result.get("ok"):
        return False, result.get("message", "تعذر إعادة الإرسال."), result
    return True, "تم إرسال رمز تحقق جديد.", result


def request_password_reset(storage, email: str) -> None:
    if not enabled() or not configured():
        return
    user = storage.get_admin_user_by_email(email)
    if not user or user.get("status") not in {"approved", "pending"}:
        return
    if user.get("status") == "pending" and not is_verified(storage, user):
        return
    token = secrets.token_urlsafe(32)
    token_hash = _reset_hash(token)
    now = int(time.time())
    expires = now + RESET_TTL_SECONDS
    created = datetime.now().isoformat(timespec="seconds")
    with storage._lock:
        with storage._connect() as con:
            cur = con.cursor()
            if storage.kind == "postgres":
                cur.execute("DELETE FROM admin_password_resets WHERE user_id=%s AND used_at IS NULL", (user["id"],))
                cur.execute(
                    "INSERT INTO admin_password_resets(token_hash,user_id,created_at,expires_at,used_at) VALUES (%s,%s,%s,%s,%s)",
                    (token_hash, user["id"], created, expires, None),
                )
            else:
                cur.execute("DELETE FROM admin_password_resets WHERE user_id=? AND used_at IS NULL", (user["id"],))
                cur.execute(
                    "INSERT INTO admin_password_resets(token_hash,user_id,created_at,expires_at,used_at) VALUES (?,?,?,?,?)",
                    (token_hash, user["id"], created, expires, None),
                )
                con.commit()
    send_reset_email(user, token)


def reset_password(storage, token: str, new_password_hash: str) -> tuple[bool, str]:
    token = str(token or "").strip()
    if not token:
        return False, "رابط إعادة التعيين غير صالح."
    token_hash = _reset_hash(token)
    row = storage._fetchone(
        "SELECT user_id,expires_at,used_at FROM admin_password_resets WHERE token_hash=%s",
        "SELECT user_id,expires_at,used_at FROM admin_password_resets WHERE token_hash=?",
        (token_hash,),
    )
    if not row:
        return False, "رابط إعادة التعيين غير صالح أو منتهي."
    user_id, expires_at, used_at = row
    now = int(time.time())
    if used_at is not None or int(expires_at) < now:
        return False, "رابط إعادة التعيين غير صالح أو منتهي."
    with storage._lock:
        with storage._connect() as con:
            cur = con.cursor()
            if storage.kind == "postgres":
                cur.execute("UPDATE admin_users SET password_hash=%s WHERE id=%s", (new_password_hash, user_id))
                cur.execute("UPDATE admin_password_resets SET used_at=%s WHERE token_hash=%s", (now, token_hash))
                cur.execute("DELETE FROM admin_sessions WHERE user_id=%s", (user_id,))
            else:
                cur.execute("UPDATE admin_users SET password_hash=? WHERE id=?", (new_password_hash, user_id))
                cur.execute("UPDATE admin_password_resets SET used_at=? WHERE token_hash=?", (now, token_hash))
                cur.execute("DELETE FROM admin_sessions WHERE user_id=?", (user_id,))
                con.commit()
    return True, "تم تحديث كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن."
