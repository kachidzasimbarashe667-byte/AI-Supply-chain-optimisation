"""Security building blocks: input validation, passwords, server-side sessions,
role-based permissions, CSRF defence and rate limiting."""
import hashlib
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import date, timedelta
from functools import wraps

from flask import current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from .db import SessionToken, User, utcnow

# --------------------------------------------------------------------------- permissions
# One place that says exactly what each department may do. The API enforces this on the
# server, so hiding a menu item in the browser is never the only line of defence.
PERMISSIONS = {
    "supplier":    {"suppliers.read_own", "forecast.read_own"},
    "procurement": {"suppliers.read_all", "inventory.read", "records.read", "records.write",
                    "forecast.read", "alerts.read"},
    "pm":          {"projects.read", "projects.request", "inventory.read", "forecast.read", "alerts.read"},
    "finance":     {"finance.read", "projects.read", "forecast.read"},
    "engineer":    {"inventory.read", "records.read", "records.write", "alerts.read"},
    "admin":       {"suppliers.read_all", "suppliers.read_own", "inventory.read", "records.read",
                    "records.write", "forecast.read", "alerts.read", "projects.read", "projects.request",
                    "finance.read", "admin.users", "admin.audit", "admin.integrity", "admin.retrain"},
}


# --------------------------------------------------------------------------- validation
class ValidationError(Exception):
    def __init__(self, errors):
        super().__init__("validation failed")
        self.errors = errors


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
NAME_RE = re.compile(r"[^\W\d_][\w .'\-]{0,79}", re.UNICODE)
ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,16}")


def clean(data, spec):
    """Strict allow-list validation. Unknown fields are rejected, every field is type-,
    length- and pattern-checked. Returns a new dict containing only validated values."""
    if not isinstance(data, dict):
        raise ValidationError({"_": "A JSON object is required."})
    errors, out = {}, {}
    extra = sorted(set(data) - set(spec))
    if extra:
        errors["_"] = "Unknown field(s): " + ", ".join(str(e)[:30] for e in extra)
    for key, rule in spec.items():
        value = data.get(key)
        if value is None or value == "":
            if rule.get("required"):
                errors[key] = "This field is required."
            continue
        kind = rule["type"]
        try:
            if kind in ("str", "email", "name", "id", "date"):
                if not isinstance(value, str):
                    raise ValueError("Must be text.")
                value = value.strip()
                if any(ord(c) < 32 for c in value):
                    raise ValueError("Control characters are not allowed.")
                if not (rule.get("min", 1) <= len(value) <= rule.get("max", 200)):
                    raise ValueError(f"Must be {rule.get('min', 1)}-{rule.get('max', 200)} characters.")
                if kind == "email":
                    value = value.lower()
                    if not EMAIL_RE.fullmatch(value):
                        raise ValueError("Enter a valid email address.")
                elif kind == "name" and not NAME_RE.fullmatch(value):
                    raise ValueError("Use letters, spaces, . ' - only.")
                elif kind == "id" and not ID_RE.fullmatch(value):
                    raise ValueError("Invalid identifier.")
                elif kind == "date":
                    d = date.fromisoformat(value)
                    if d > date.today() + timedelta(days=1) or d.year < 2015:
                        raise ValueError("Date is out of range.")
                    value = d
                if "pattern" in rule and not re.fullmatch(rule["pattern"], str(value)):
                    raise ValueError("Invalid format.")
            elif kind in ("int", "float"):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError("Must be a number.")
                value = int(value) if kind == "int" else float(value)
                if value != value or value in (float("inf"), float("-inf")):
                    raise ValueError("Must be a finite number.")
                if not (rule.get("minv", -1e12) <= value <= rule.get("maxv", 1e12)):
                    raise ValueError(f"Must be between {rule.get('minv', '-inf')} and {rule.get('maxv', 'inf')}.")
            elif kind == "password":
                if not isinstance(value, str):
                    raise ValueError("Must be text.")
                problem = password_problem(value)
                if problem:
                    raise ValueError(problem)
            if "choices" in rule and value not in rule["choices"]:
                raise ValueError("Not an allowed value.")
        except ValueError as exc:
            errors[key] = str(exc)
            continue
        out[key] = value
    if errors:
        raise ValidationError(errors)
    return out


# --------------------------------------------------------------------------- passwords
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def password_problem(pw: str):
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    if len(pw) > 128:
        return "Password is too long."
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)):
        return "Use upper-case, lower-case and a number."
    return None


def hash_password(pw: str) -> str:
    return generate_password_hash(pw)          # scrypt + per-password random salt


def verify_password(user, pw: str) -> bool:
    """Runs a hash check even when the user does not exist, so response time does not
    reveal which emails are registered."""
    return check_password_hash(user.password_hash if user else _DUMMY_HASH, pw) and user is not None


# --------------------------------------------------------------------------- sessions
def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user) -> str:
    cfg = current_app.config
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(SessionToken(token_hash=_digest(token), user_id=user.id, created_at=now, last_seen=now,
                        expires_at=now + timedelta(hours=cfg["SESSION_ABSOLUTE_HOURS"]),
                        ip=(request.remote_addr or "")[:45]))
    db.commit()
    return token


def load_session_user(db, token):
    """Return the active user for this cookie, or None. Enforces absolute + idle timeouts."""
    if not token or len(token) > 100:
        return None
    row = db.query(SessionToken).filter(SessionToken.token_hash == _digest(token)).one_or_none()
    if row is None:
        return None
    now = utcnow()
    idle = timedelta(minutes=current_app.config["SESSION_IDLE_MINUTES"])
    if row.expires_at < now or now - row.last_seen > idle or row.user.status != "active":
        db.delete(row)
        db.commit()
        return None
    row.last_seen = now
    db.commit()
    return row.user


def destroy_session(db, token):
    if token:
        db.query(SessionToken).filter(SessionToken.token_hash == _digest(token)).delete()
        db.commit()


def destroy_user_sessions(db, user_id):
    db.query(SessionToken).filter(SessionToken.user_id == user_id).delete()


# --------------------------------------------------------------------------- rate limiting
_hits = defaultdict(deque)


def rate_limited(bucket: str) -> bool:
    limit, window = current_app.config["RATE_LIMIT_AUTH"]
    key = f"{bucket}:{request.remote_addr}"
    now, q = time.monotonic(), _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def reset_rate_limits():
    _hits.clear()


# --------------------------------------------------------------------------- decorators
def error(message, status=400, **extra):
    return jsonify({"error": message, **extra}), status


def require(permission=None):
    """Authenticate the cookie session, then check the role holds `permission`."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = g.get("user")
            if user is None:
                return error("Sign in required.", 401)
            if permission and permission not in PERMISSIONS.get(user.role, ()):
                return error("Your role is not allowed to do that.", 403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def csrf_guard():
    """State-changing requests must be JSON, carry our custom header and come from our own
    origin. Combined with SameSite=Strict cookies this blocks cross-site request forgery."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("X-Requested-With") != "leengate":
            return error("Missing X-Requested-With header.", 403)
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != request.host:
            return error("Cross-origin request blocked.", 403)
        if request.content_length and not request.is_json:
            return error("JSON body required.", 415)
    return None
