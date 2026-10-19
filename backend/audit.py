"""Append-only audit trail (the database refuses UPDATE / DELETE on this table)."""
from flask import g, request

from .db import AuditLog


def log_action(action: str, detail: str = "", user=None, actor=None):
    user = user or g.get("user")
    entry = AuditLog(user_id=user.id if user else None,
                     actor=actor or (f"{user.name} ({user.role})" if user else "anonymous"),
                     action=action[:60], detail=detail[:1000], ip=(request.remote_addr or "")[:45])
    g.db.add(entry)
    g.db.commit()
