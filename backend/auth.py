"""Sign-in, sign-out and 'who am I'. Sessions live on the server. (No self-registration: accounts are provisioned.)"""
from datetime import timedelta

from flask import Blueprint, current_app, g, jsonify, make_response, request

from .audit import log_action
from .db import User, utcnow
from .security import (ValidationError, clean, create_session, destroy_session, error,
                       rate_limited, require, verify_password)

bp = Blueprint("auth", __name__)

LOGIN = {"email": {"type": "email", "required": True},
         "password": {"type": "str", "required": True, "max": 128}}


def public_user(u):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "supplier_id": u.supplier_id}


@bp.post("/login")
def login():
    if rate_limited("auth"):
        return error("Too many attempts. Try again in a minute.", 429)
    try:
        data = clean(request.get_json(silent=True), LOGIN)
    except ValidationError:
        return error("Invalid email or password.", 401)          # deliberately vague
    cfg, now = current_app.config, utcnow()
    user = g.db.query(User).filter(User.email == data["email"]).one_or_none()
    if user and user.locked_until and user.locked_until > now:
        log_action("login_blocked", "account locked", user=user)
        return error("Account temporarily locked. Try again later.", 423)
    if not verify_password(user, data["password"]):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= cfg["MAX_FAILED_LOGINS"]:
                user.locked_until = now + timedelta(minutes=cfg["LOCKOUT_MINUTES"])
                user.failed_logins = 0
            g.db.commit()
            log_action("login_failed", user.email, user=user)
        return error("Invalid email or password.", 401)
    if user.status != "active":
        return error("Your account is awaiting approval or has been disabled.", 403)
    user.failed_logins, user.locked_until = 0, None
    g.db.commit()
    token = create_session(g.db, user)
    log_action("login", "signed in", user=user)
    resp = make_response(jsonify({"user": public_user(user)}))
    resp.set_cookie(cfg["COOKIE_NAME"], token, httponly=True, samesite="Strict", secure=cfg["COOKIE_SECURE"],
                    max_age=cfg["SESSION_ABSOLUTE_HOURS"] * 3600, path="/")
    return resp


@bp.post("/logout")
def logout():
    cfg = current_app.config
    if g.user:
        log_action("logout", "signed out")
    destroy_session(g.db, request.cookies.get(cfg["COOKIE_NAME"]))
    resp = make_response(jsonify({"message": "Signed out."}))
    resp.delete_cookie(cfg["COOKIE_NAME"], path="/", samesite="Strict")
    # Tell the browser to throw away cached pages, cookies and local/session storage for this site
    resp.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return resp


@bp.get("/me")
@require()
def me():
    return jsonify({"user": public_user(g.user)})
