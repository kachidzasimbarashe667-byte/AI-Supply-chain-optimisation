"""Database layer.

Security design
---------------
* Every query goes through the SQLAlchemy ORM / Core, which sends user input to the
  database as *bound parameters*, never as part of the SQL text. That is what actually
  defeats SQL injection. There is no string-built SQL anywhere in this project
  (tests/test_security.py scans the source to make sure it stays that way).
* The schema itself enforces the rules (NOT NULL, UNIQUE, FOREIGN KEY, CHECK), so bad
  data is rejected even if application code has a bug.
* The audit log is append-only: database triggers refuse UPDATE and DELETE.
"""
from datetime import datetime, timezone

from sqlalchemy import (CheckConstraint, DDL, Date, DateTime, Float, ForeignKey, Integer,
                        String, Text, UniqueConstraint, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, scoped_session, sessionmaker

ROLES = ("supplier", "procurement", "pm", "finance", "engineer", "admin")
STATUSES = ("pending", "active", "disabled")
PROJECT_STATUSES = ("complete", "in-progress", "not-started")
REQUEST_STATUSES = ("open", "approved", "rejected", "fulfilled")


def utcnow() -> datetime:
    """Naive UTC timestamp (works the same on SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- people
class Supplier(Base):
    __tablename__ = "suppliers"
    id: Mapped[str] = mapped_column(String(4), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    city: Mapped[str] = mapped_column(String(60), nullable=False)
    reliability: Mapped[float] = mapped_column(Float, nullable=False)
    ontime: Mapped[float] = mapped_column(Float, nullable=False)
    lead_days: Mapped[float] = mapped_column(Float, nullable=False)
    defect_rate: Mapped[float] = mapped_column(Float, nullable=False)
    cost_index: Mapped[float] = mapped_column(Float, nullable=False)
    risk: Mapped[float] = mapped_column(Float, nullable=False)
    capacity: Mapped[float] = mapped_column(Float, nullable=False)
    capacity_unit: Mapped[str] = mapped_column(String(20), nullable=False)
    __table_args__ = (
        CheckConstraint("reliability BETWEEN 0 AND 100", name="ck_supplier_reliability"),
        CheckConstraint("ontime BETWEEN 0 AND 100", name="ck_supplier_ontime"),
        CheckConstraint("risk BETWEEN 0 AND 100", name="ck_supplier_risk"),
        CheckConstraint("defect_rate BETWEEN 0 AND 100", name="ck_supplier_defect"),
        CheckConstraint("lead_days >= 0", name="ck_supplier_lead"),
        CheckConstraint("capacity >= 0", name="ck_supplier_capacity"),
    )


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    supplier_id: Mapped[str | None] = mapped_column(ForeignKey("suppliers.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="pending")
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    __table_args__ = (
        CheckConstraint("role IN (%s)" % ",".join(f"'{r}'" for r in ROLES), name="ck_user_role"),
        CheckConstraint("status IN (%s)" % ",".join(f"'{s}'" for s in STATUSES), name="ck_user_status"),
        # a supplier account must belong to a supplier company; nobody else may
        CheckConstraint("(role = 'supplier') = (supplier_id IS NOT NULL)", name="ck_user_supplier_link"),
    )


class SessionToken(Base):
    """Server-side sessions. Only a SHA-256 hash of the token is stored, so a leaked
    database cannot be used to hijack live sessions. Deleting the row = signed out."""
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(45))
    user: Mapped[User] = relationship()


# --------------------------------------------------------------------------- supply chain
class Material(Base):
    __tablename__ = "materials"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    unit: Mapped[str] = mapped_column(String(20), nullable=False)
    unit_cost: Mapped[float] = mapped_column(Float, nullable=False)
    lead_days: Mapped[float] = mapped_column(Float, nullable=False)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"), nullable=False)
    stock: Mapped[float] = mapped_column(Float, nullable=False)
    reorder_point: Mapped[float] = mapped_column(Float, nullable=False)
    supplier: Mapped[Supplier] = relationship()
    demand: Mapped[list["MonthlyDemand"]] = relationship(viewonly=True, order_by="MonthlyDemand.period")
    __table_args__ = (
        CheckConstraint("unit_cost > 0", name="ck_material_cost"),
        CheckConstraint("stock >= 0", name="ck_material_stock"),
        CheckConstraint("reorder_point >= 0", name="ck_material_rop"),
        CheckConstraint("lead_days >= 0", name="ck_material_lead"),
    )


class MonthlyDemand(Base):
    """36 months of consumption per material - the training data for XGBoost."""
    __tablename__ = "monthly_demand"
    id: Mapped[int] = mapped_column(primary_key=True)
    material_id: Mapped[str] = mapped_column(ForeignKey("materials.id", ondelete="CASCADE"), nullable=False)
    period: Mapped[int] = mapped_column(Integer, nullable=False)       # 0 = oldest month
    month: Mapped[int] = mapped_column(Integer, nullable=False)        # calendar month 1-12
    quantity: Mapped[float] = mapped_column(Float, nullable=False)
    __table_args__ = (
        UniqueConstraint("material_id", "period", name="uq_demand_period"),
        CheckConstraint("month BETWEEN 1 AND 12", name="ck_demand_month"),
        CheckConstraint("quantity >= 0", name="ck_demand_qty"),
    )


class Route(Base):
    __tablename__ = "routes"
    id: Mapped[str] = mapped_column(String(4), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"), nullable=False)
    transit_days: Mapped[float] = mapped_column(Float, nullable=False)
    base_delay_rate: Mapped[float] = mapped_column(Float, nullable=False)
    supplier: Mapped[Supplier] = relationship()
    __table_args__ = (CheckConstraint("base_delay_rate BETWEEN 0 AND 1", name="ck_route_delay"),
                      CheckConstraint("transit_days > 0", name="ck_route_days"))


class Shipment(Base):
    """Historic deliveries - the training data for the delayed-route XGBoost classifier."""
    __tablename__ = "shipments"
    id: Mapped[int] = mapped_column(primary_key=True)
    route_id: Mapped[str] = mapped_column(ForeignKey("routes.id", ondelete="CASCADE"), nullable=False, index=True)
    period: Mapped[int] = mapped_column(Integer, nullable=False)
    month: Mapped[int] = mapped_column(Integer, nullable=False)
    planned_days: Mapped[float] = mapped_column(Float, nullable=False)
    actual_days: Mapped[float] = mapped_column(Float, nullable=False)
    delayed: Mapped[int] = mapped_column(Integer, nullable=False)
    __table_args__ = (CheckConstraint("delayed IN (0,1)", name="ck_shipment_delayed"),
                      CheckConstraint("month BETWEEN 1 AND 12", name="ck_shipment_month"),
                      CheckConstraint("planned_days > 0 AND actual_days > 0", name="ck_shipment_days"))


# --------------------------------------------------------------------------- projects & money
class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    location: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    progress: Mapped[int] = mapped_column(Integer, nullable=False)
    budget: Mapped[float] = mapped_column(Float, nullable=False)
    spent: Mapped[float] = mapped_column(Float, nullable=False)
    equipment: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    needs: Mapped[list["ProjectNeed"]] = relationship(cascade="all, delete-orphan")
    __table_args__ = (
        CheckConstraint("status IN (%s)" % ",".join(f"'{s}'" for s in PROJECT_STATUSES), name="ck_project_status"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="ck_project_progress"),
        CheckConstraint("budget >= 0 AND spent >= 0", name="ck_project_money"),
        CheckConstraint("spent <= budget * 1.5", name="ck_project_overspend"),
    )


class ProjectNeed(Base):
    __tablename__ = "project_needs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    material_id: Mapped[str] = mapped_column(ForeignKey("materials.id"), nullable=False)
    quantity: Mapped[float] = mapped_column(Float, nullable=False)
    __table_args__ = (UniqueConstraint("project_id", "material_id", name="uq_need"),
                      CheckConstraint("quantity > 0", name="ck_need_qty"))


class ItemRequest(Base):
    __tablename__ = "item_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    note: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    project: Mapped[Project] = relationship()
    __table_args__ = (CheckConstraint("status IN (%s)" % ",".join(f"'{s}'" for s in REQUEST_STATUSES), name="ck_request_status"),)


class DataRecord(Base):
    """Manually captured procurement / delivery records (the 'Add a record' form)."""
    __tablename__ = "data_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"), nullable=False, index=True)
    material_id: Mapped[str] = mapped_column(ForeignKey("materials.id"), nullable=False, index=True)
    quantity: Mapped[float] = mapped_column(Float, nullable=False)
    record_date: Mapped[datetime] = mapped_column(Date, nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    supplier: Mapped[Supplier] = relationship()
    material: Mapped[Material] = relationship()
    __table_args__ = (CheckConstraint("quantity > 0", name="ck_record_qty"),)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ip: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


# Append-only audit trail enforced by the database itself (nobody can quietly edit history)
for _ddl in (
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
):
    event.listen(AuditLog.__table__, "after_create", DDL(_ddl).execute_if(dialect="sqlite"))


# --------------------------------------------------------------------------- engine
def make_engine(url: str):
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)

    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")     # enforce FOREIGN KEYs
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA secure_delete=ON")    # overwrite deleted data
            cur.close()
    return engine


def make_session_factory(engine):
    return scoped_session(sessionmaker(bind=engine, autoflush=False, expire_on_commit=False))
