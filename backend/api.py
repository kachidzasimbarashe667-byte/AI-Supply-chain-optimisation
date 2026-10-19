"""REST API. Every endpoint states which permission it needs; the role -> permission map
lives in security.PERMISSIONS. All database access is through the ORM (bound parameters)."""
import math

import numpy as np
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import text

from .audit import log_action
from .auth import public_user
from .db import (AuditLog, DataRecord, ItemRequest, Material, MonthlyDemand, Project, Route, Supplier,
                 User, SessionToken, utcnow)
from .security import (PERMISSIONS, ValidationError, clean, destroy_user_sessions, error, hash_password,
                       password_problem, require)

bp = Blueprint("api", __name__)


# --------------------------------------------------------------------------- helpers
def ml():
    return current_app.extensions["ml"]


def can(permission):
    return permission in PERMISSIONS.get(g.user.role, ())


def next_month():
    last = g.db.query(MonthlyDemand).order_by(MonthlyDemand.period.desc()).first()
    return (last.month % 12 + 1) if last else 1


def validation_failed(exc):
    return error("Please correct the highlighted fields.", 422, fields=exc.errors)


def supplier_json(s):
    return {"id": s.id, "name": s.name, "category": s.category, "city": s.city, "reliability": s.reliability,
            "ontime": s.ontime, "lead_days": s.lead_days, "defect_rate": s.defect_rate, "cost_index": s.cost_index,
            "risk": s.risk, "capacity": s.capacity, "capacity_unit": s.capacity_unit,
            "score": round(s.reliability * .35 + s.ontime * .3 + (100 - s.risk) * .2 + (100 - s.defect_rate * 8) * .15)}


def inventory_rows():
    rows = []
    for m in g.db.query(Material).order_by(Material.id).all():
        f = ml().forecast(m.id, 1)
        nxt = f[0]["quantity"] if f else 0.0
        daily = nxt / 30
        ratio = m.stock / m.reorder_point if m.reorder_point else 9

        hist = [h.quantity for h in sorted(m.demand, key=lambda h: h.period)]
        recent = hist[-24:] if len(hist) >= 24 else hist
        if len(recent) >= 4:
            x = np.arange(len(recent))
            slope, intercept = np.polyfit(x, recent, 1)
            resid_std = float(np.std(recent - (slope * x + intercept))) or 1.0
        else:
            resid_std = float(np.std(recent)) if recent else 1.0
        lead = m.lead_days
        safety_stock = min(m.reorder_point * .9, 1.65 * (resid_std / math.sqrt(30)) * math.sqrt(lead))
        annual_demand = daily * 365
        holding_cost = max(m.unit_cost * .2, .001)
        eoq = math.sqrt(2 * annual_demand * 150 / holding_cost)
        lead_time_demand = nxt / 30 * lead
        spread = resid_std / math.sqrt(30) * math.sqrt(lead) + 1e-9
        stockout_p = 1 - _norm_cdf((m.stock - lead_time_demand) / spread)
        overstock_p = _norm_cdf((m.stock - lead_time_demand - 2.2 * m.reorder_point) / spread)

        rows.append({"material_id": m.id, "material": m.name, "unit": m.unit, "supplier": m.supplier.name,
                     "stock": m.stock, "reorder_point": m.reorder_point, "safety_stock": round(safety_stock, 1),
                     "eoq": round(eoq, 1), "predicted_next_month": round(nxt, 1),
                     "stockout_probability": round(max(0, min(1, stockout_p)) * 100, 1),
                     "overstock_probability": round(max(0, min(1, overstock_p)) * 100, 1),
                     "days_of_cover": round(m.stock / daily, 1) if daily else None,
                     "status": "critical" if ratio < .5 else "low" if ratio < 1 else "excess" if ratio > 2.5 else "optimal"})
    return rows


def _norm_cdf(x):
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def route_risk_rows():
    return sorted(ml().route_risk(g.db, next_month()), key=lambda r: -r["delay_probability"])


# --------------------------------------------------------------------------- public
@bp.get("/health")
def health():
    return jsonify({"status": "ok", "service": "leengate-backend"})


@bp.get("/public/suppliers")
def public_suppliers():
    """Names only, no auth - just enough for the sign-up form's 'which company' picker."""
    rows = g.db.query(Supplier).order_by(Supplier.name).all()
    return jsonify({"suppliers": [{"id": s.id, "name": s.name, "category": s.category} for s in rows]})


@bp.get("/materials")
@require()
def materials():
    rows = g.db.query(Material).order_by(Material.id).all()
    return jsonify({"materials": [{"id": m.id, "name": m.name, "unit": m.unit, "unit_cost": m.unit_cost,
                                   "lead_days": m.lead_days, "supplier_id": m.supplier_id,
                                   "supplier": m.supplier.name, "stock": m.stock,
                                   "reorder_point": m.reorder_point} for m in rows]})


@bp.get("/materials/<material_id>/history")
@require()
def material_history(material_id):
    m = g.db.get(Material, material_id)
    if m is None:
        return error("Unknown material.", 404)
    rows = (g.db.query(MonthlyDemand).filter(MonthlyDemand.material_id == material_id)
            .order_by(MonthlyDemand.period).all())
    return jsonify({"material_id": material_id, "unit": m.unit,
                    "history": [{"period": r.period, "month": r.month, "quantity": r.quantity} for r in rows]})


# --------------------------------------------------------------------------- suppliers
@bp.get("/suppliers")
@require("suppliers.read_all")
def suppliers():
    return jsonify({"suppliers": [supplier_json(s) for s in g.db.query(Supplier).order_by(Supplier.id)]})


@bp.get("/suppliers/me")
@require("suppliers.read_own")
def my_supplier():
    """A supplier sees only their own company: performance, what they supply to Leengate,
    and the XGBoost forecast of Leengate's demand for it (so they can plan stock)."""
    if not g.user.supplier_id:
        return error("Your account is not linked to a supplier company.", 404)
    s = g.db.get(Supplier, g.user.supplier_id)
    mats = g.db.query(Material).filter(Material.supplier_id == s.id).all()
    return jsonify({"supplier": supplier_json(s),
                    "supplies": [{"material_id": m.id, "material": m.name, "unit": m.unit,
                                  "leengate_stock": m.stock, "reorder_point": m.reorder_point,
                                  "demand_forecast": ml().forecast(m.id, 6)} for m in mats]})


# --------------------------------------------------------------------------- forecasts (XGBoost)
@bp.get("/forecast/<material_id>")
@require()
def forecast(material_id):
    try:
        args = clean({"months": int(request.args.get("months", 6))}, {"months": {"type": "int", "minv": 1, "maxv": 12}})
        clean({"id": material_id}, {"id": {"type": "id", "required": True}})
    except (ValidationError, ValueError):
        return error("months must be a whole number from 1 to 12; material id is invalid.", 422)
    m = g.db.get(Material, material_id)
    if m is None:
        return error("Unknown material.", 404)
    if can("forecast.read"):
        pass
    elif can("forecast.read_own") and g.user.supplier_id == m.supplier_id:
        pass
    else:
        return error("Your role is not allowed to do that.", 403)
    return jsonify({"material": m.name, "unit": m.unit, "model": "XGBoost",
                    "accuracy": ml().demand[m.id]["metrics"] if m.id in ml().demand else None,
                    "forecast": ml().forecast(m.id, args["months"])})


@bp.get("/forecast-summary")
@require("forecast.read")
def forecast_summary():
    ml().ensure()
    rows, total = [], 0.0
    for m in g.db.query(Material).order_by(Material.id).all():
        f = ml().forecast(m.id, 1)
        if not f:
            continue
        q = f[0]["quantity"]
        rows.append({"material_id": m.id, "material": m.name, "unit": m.unit, "predicted_quantity": q,
                     "unit_cost": m.unit_cost, "predicted_cost": round(q * m.unit_cost, 2),
                     "accuracy": ml().demand[m.id]["metrics"]["accuracy"]})
        total += q * m.unit_cost
    return jsonify({"model": "XGBoost", "horizon": "next month", "materials": rows, "total_cost": round(total, 2)})


# --------------------------------------------------------------------------- stock & routes
@bp.get("/inventory")
@require("inventory.read")
def inventory():
    return jsonify({"inventory": inventory_rows()})


@bp.get("/route-risk")
@require("alerts.read")
def route_risk():
    return jsonify({"model": "XGBoost classifier", "routes": route_risk_rows()})


@bp.get("/alerts")
@require("alerts.read")
def alerts():
    out = []
    for r in inventory_rows():
        if r["status"] in ("critical", "low"):
            out.append({"type": "low_stock", "severity": "high" if r["status"] == "critical" else "medium",
                        "title": f"{r['material']} running low",
                        "detail": f"{r['stock']:.0f} {r['unit']} in stock, reorder point {r['reorder_point']:.0f}; "
                                  f"about {r['days_of_cover']} days of cover at the predicted demand."})
    for r in route_risk_rows():
        if r["delay_probability"] >= .25:
            out.append({"type": "route_delay", "severity": "high" if r["delay_probability"] >= .4 else "medium",
                        "title": f"{r['route']} - delay risk",
                        "detail": f"{round(r['delay_probability'] * 100)}% predicted chance of a late delivery next month."})
    return jsonify({"alerts": out})


# --------------------------------------------------------------------------- projects & finance
def project_json(p, with_money=True):
    inv = {m.id: m for m in g.db.query(Material).all()}
    out = {"id": p.id, "name": p.name, "location": p.location, "status": p.status, "progress": p.progress,
           "equipment": [e.strip() for e in p.equipment.split(",") if e.strip()],
           "needs": [{"material_id": n.material_id, "material": inv[n.material_id].name,
                      "unit": inv[n.material_id].unit, "quantity": n.quantity} for n in p.needs]}
    if with_money:
        out.update({"budget": p.budget, "spent": p.spent, "remaining": p.budget - p.spent})
    return out


@bp.get("/projects")
@require("projects.read")
def projects():
    return jsonify({"projects": [project_json(p) for p in g.db.query(Project).order_by(Project.id)]})


@bp.get("/item-requests")
@require("projects.read")
def list_requests():
    rows = g.db.query(ItemRequest).order_by(ItemRequest.id.desc()).limit(100).all()
    return jsonify({"requests": [{"id": r.id, "project": r.project.name, "status": r.status, "note": r.note,
                                  "created_at": r.created_at.isoformat()} for r in rows]})


@bp.post("/item-requests")
@require("projects.request")
def create_request():
    try:
        data = clean(request.get_json(silent=True), {"project_id": {"type": "id", "required": True},
                                                     "note": {"type": "str", "max": 300}})
    except ValidationError as exc:
        return validation_failed(exc)
    project = g.db.get(Project, data["project_id"])
    if project is None:
        return error("Unknown project.", 404)
    if project.status == "complete":
        return error("This project is already complete.", 409)
    req = ItemRequest(project_id=project.id, requested_by=g.user.id, note=data.get("note"))
    g.db.add(req)
    g.db.commit()
    log_action("item_request", f"Items requested for {project.name}")
    return jsonify({"request": {"id": req.id, "project": project.name, "status": req.status}}), 201


@bp.get("/finance/summary")
@require("finance.read")
def finance_summary():
    projs = g.db.query(Project).order_by(Project.id).all()
    open_projects = [p for p in projs if p.status != "complete"]
    return jsonify({
        "total_budget": sum(p.budget for p in projs), "spent": sum(p.spent for p in projs),
        "funding_needed": sum(p.budget - p.spent for p in open_projects),
        "awaiting_funding": [{"id": p.id, "name": p.name, "needs": p.budget, "location": p.location}
                             for p in projs if p.status == "not-started"],
        "projects": [project_json(p) for p in projs]})


# --------------------------------------------------------------------------- data records (input & manage)
def _names():
    return ([s.name for s in g.db.query(Supplier).all()], [m.name for m in g.db.query(Material).all()])


def record_json(r):
    return {"id": r.id, "supplier": r.supplier.name, "material": r.material.name, "quantity": r.quantity,
            "date": r.record_date.isoformat(), "created_by": r.created_by}


@bp.get("/records")
@require("records.read")
def list_records():
    sup_names, mat_names = _names()
    try:
        args = clean(dict(request.args), {"supplier": {"type": "str", "choices": sup_names},
                                          "material": {"type": "str", "choices": mat_names},
                                          "limit": {"type": "str", "pattern": r"\d{1,3}", "max": 3}})
    except ValidationError as exc:
        return validation_failed(exc)
    q = g.db.query(DataRecord).join(Supplier).join(Material)
    if "supplier" in args:
        q = q.filter(Supplier.name == args["supplier"])         # bound parameter
    if "material" in args:
        q = q.filter(Material.name == args["material"])
    rows = q.order_by(DataRecord.id.desc()).limit(min(int(args.get("limit", 50)), 200)).all()
    return jsonify({"records": [record_json(r) for r in rows]})


@bp.post("/records")
@require("records.write")
def add_record():
    sup_names, mat_names = _names()
    try:
        data = clean(request.get_json(silent=True), {
            "supplier": {"type": "str", "required": True, "choices": sup_names},
            "material": {"type": "str", "required": True, "choices": mat_names},
            "quantity": {"type": "float", "required": True, "minv": 0.0001, "maxv": 10_000_000},
            "date": {"type": "date", "required": True}})
    except ValidationError as exc:
        return validation_failed(exc)
    sup = g.db.query(Supplier).filter(Supplier.name == data["supplier"]).one()
    mat = g.db.query(Material).filter(Material.name == data["material"]).one()
    rec = DataRecord(supplier_id=sup.id, material_id=mat.id, quantity=data["quantity"],
                     record_date=data["date"], created_by=g.user.id)
    g.db.add(rec)
    g.db.commit()
    log_action("record_added", f"{mat.name} x {data['quantity']} from {sup.name}")
    return jsonify({"record": record_json(rec)}), 201


@bp.delete("/records/<int:record_id>")
@require("records.write")
def delete_record(record_id):
    rec = g.db.get(DataRecord, record_id)
    if rec is None:
        return error("Record not found.", 404)
    if rec.created_by != g.user.id and g.user.role not in ("admin", "procurement"):
        return error("You can only delete records you created.", 403)
    g.db.delete(rec)
    g.db.commit()
    log_action("record_deleted", f"record {record_id}")
    return jsonify({"message": "Deleted."})


# --------------------------------------------------------------------------- IT / AI management
@bp.get("/admin/users")
@require("admin.users")
def admin_users():
    rows = g.db.query(User).order_by(User.id).all()
    return jsonify({"users": [{**public_user(u), "status": u.status, "created_at": u.created_at.isoformat()} for u in rows]})


@bp.post("/admin/users")
@require("admin.users")
def admin_create_user():
    try:
        data = clean(request.get_json(silent=True), {
            "name": {"type": "name", "required": True}, "email": {"type": "email", "required": True},
            "password": {"type": "password", "required": True},
            "role": {"type": "str", "required": True, "choices": tuple(PERMISSIONS)},
            "supplier_id": {"type": "id"}})
    except ValidationError as exc:
        return validation_failed(exc)
    if (data["role"] == "supplier") != bool(data.get("supplier_id")):
        return error("Supplier accounts need a supplier company; other roles must not have one.", 422)
    if data.get("supplier_id") and g.db.get(Supplier, data["supplier_id"]) is None:
        return error("Unknown supplier company.", 422)
    if g.db.query(User).filter(User.email == data["email"]).first():
        return error("That email is already registered.", 409)
    u = User(name=data["name"], email=data["email"], password_hash=hash_password(data["password"]),
             role=data["role"], supplier_id=data.get("supplier_id"), status="active")
    g.db.add(u)
    g.db.commit()
    log_action("user_created", f"{u.email} as {u.role}")
    return jsonify({"user": public_user(u)}), 201


@bp.patch("/admin/users/<int:user_id>")
@require("admin.users")
def admin_update_user(user_id):
    try:
        data = clean(request.get_json(silent=True), {
            "status": {"type": "str", "choices": ("pending", "active", "disabled")},
            "role": {"type": "str", "choices": tuple(PERMISSIONS)}})
    except ValidationError as exc:
        return validation_failed(exc)
    u = g.db.get(User, user_id)
    if u is None:
        return error("User not found.", 404)
    if u.id == g.user.id and data.get("status") in ("disabled", "pending"):
        return error("You cannot disable your own account.", 409)
    if "role" in data:
        if (data["role"] == "supplier") != bool(u.supplier_id):
            return error("Role does not match the account's supplier link.", 422)
        u.role = data["role"]
        destroy_user_sessions(g.db, u.id)                    # role change = sign in again
    if "status" in data:
        u.status = data["status"]
        if data["status"] != "active":
            destroy_user_sessions(g.db, u.id)                # disabling ends live sessions immediately
    g.db.commit()
    log_action("user_updated", f"{u.email}: {data}")
    return jsonify({"user": {**public_user(u), "status": u.status}})


@bp.get("/admin/audit")
@require("admin.audit")
def admin_audit():
    try:
        limit = clean({"limit": int(request.args.get("limit", 100))}, {"limit": {"type": "int", "minv": 1, "maxv": 500}})["limit"]
    except (ValidationError, ValueError):
        return error("limit must be 1-500.", 422)
    rows = g.db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return jsonify({"audit": [{"id": a.id, "actor": a.actor, "action": a.action, "detail": a.detail,
                               "ip": a.ip, "at": a.created_at.isoformat()} for a in rows]})


@bp.post("/admin/retrain")
@require("admin.retrain")
def admin_retrain():
    metrics = ml().train_all()
    log_action("models_retrained", f"{len(metrics['demand'])} demand models + route model")
    return jsonify({"metrics": metrics})


@bp.get("/admin/diagnostics")
@require("admin.retrain")
def admin_diagnostics():
    """Hyperparameters and feature importance read directly off the fitted XGBoost
    models - not hardcoded figures - for the IT/AI Management model console."""
    ml().ensure()
    return jsonify(ml().diagnostics())


@bp.get("/admin/integrity")
@require("admin.integrity")
def admin_integrity():
    db, checks = g.db, []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    if db.bind.dialect.name == "sqlite":
        add("Database file integrity", db.execute(text("PRAGMA integrity_check")).scalar() == "ok")
        add("Foreign keys consistent", not db.execute(text("PRAGMA foreign_key_check")).fetchall())
        triggers = {r[0] for r in db.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'"))}
        add("Audit log is append-only (triggers present)", {"audit_log_no_update", "audit_log_no_delete"} <= triggers)
    orphans = (db.query(DataRecord).outerjoin(Supplier, DataRecord.supplier_id == Supplier.id)
               .filter(Supplier.id.is_(None)).count())
    add("No data records without a supplier", orphans == 0, f"{orphans} orphaned")
    add("No negative stock levels", db.query(Material).filter(Material.stock < 0).count() == 0)
    add("Supplier accounts all linked to a company",
        db.query(User).filter(User.role == "supplier", User.supplier_id.is_(None)).count() == 0)
    add("Admin accounts exist", db.query(User).filter(User.role == "admin", User.status == "active").count() >= 1)
    add("Demand history complete (36 months per material)",
        all(db.query(MonthlyDemand).filter(MonthlyDemand.material_id == m.id).count() == 36
            for m in db.query(Material).all()))
    ml().ensure()
    add("XGBoost demand models trained", len(ml().demand) == db.query(Material).count(),
        f"{len(ml().demand)} models")
    add("XGBoost route-delay model trained", ml().route_model is not None)
    stale = db.query(SessionToken).filter(SessionToken.expires_at < utcnow()).count()
    add("No expired sessions lingering", stale == 0, f"{stale} expired")
    return jsonify({"ok": all(c["ok"] for c in checks), "checks": checks, "models": ml().metrics()})
