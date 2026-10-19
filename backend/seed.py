"""Seed the database with the Leengate case-study data.

Supplier names are real Zimbabwean businesses used for realism in this academic project.
All performance figures, demand history and shipments are SIMULATED example data - they
are not real assessments of those companies.
"""
import math
from datetime import date

import numpy as np

from .db import (Material, MonthlyDemand, Project, ProjectNeed, Route, Shipment, Supplier, User)
from .security import hash_password

SUPPLIERS = [
    # id, name, category, city, reliability, ontime, lead, defect, cost, risk, capacity, unit
    ("A", "PPC Zimbabwe", "Cement", "Harare", 91, 92, 5.8, 1.2, 96, 22, 2400, "bags/week"),
    ("B", "Steelmate", "Steel rebar", "Harare (Mbare)", 71, 69, 15.6, 2.9, 104, 68, 140, "tonnes/week"),
    ("C", "Davis Granite", "River sand & crushed aggregate", "Bulawayo", 86, 88, 3.4, 1.8, 92, 31, 1900, "m3/week"),
    ("D", "Willdale Limited", "Bricks", "Harare", 80, 81, 5.9, 3.4, 98, 44, 13000, "units/week"),
    ("E", "Zuva Petroleum", "Diesel", "Harare", 87, 89, 2.1, 0.3, 101, 24, 9500, "litres/week"),
    ("F", "Powerspeed Electrical", "Electrical equipment", "Harare", 83, 80, 6.2, 1.5, 99, 36, 800, "orders/week"),
    ("G", "Turnall Holdings", "Plumbing materials", "Harare", 78, 75, 7.4, 2.1, 97, 41, 600, "orders/week"),
    ("H", "Zimplow Holdings (Barzem)", "Truck & machinery parts, repairs", "Harare", 75, 73, 8.9, 1.9, 103, 47, 450, "orders/week"),
]

# id, name, unit, base, growth, seasonality, noise, lead, unit cost, supplier, stock/reorder ratio
MATERIALS = [
    ("cement", "Cement", "bags", 8200, .006, .14, .09, 6, 9.5, "A", .9),
    ("steel", "Steel rebar", "tonnes", 420, .009, .10, .11, 14, 980, "B", .78),
    ("sand", "River sand", "m3", 3100, .004, .17, .10, 3, 22, "C", 1.25),
    ("agg", "Crushed aggregate", "m3", 4300, .005, .15, .09, 4, 28, "C", 2.9),
    ("brick", "Bricks", "units", 52000, .003, .12, .10, 5, .14, "D", 1.4),
    ("diesel", "Diesel", "litres", 38000, .007, .07, .08, 2, 1.45, "E", .14),
]

ROUTES = [
    ("R1", "PPC Zimbabwe -> Borrowdale Office Park", "A", 1.2, .10),
    ("R2", "Steelmate -> Ruwa Housing Phase 2", "B", 2.0, .28),
    ("R3", "Davis Granite -> Mutare-Nyanga Access Road", "C", 3.5, .18),
    ("R4", "Willdale -> Norton Retail Complex", "D", 1.5, .22),
    ("R5", "Zuva Petroleum -> Bindura Bridge", "E", 2.2, .12),
]

PROJECTS = [
    ("P1", "Borrowdale Office Park", "Harare", "in-progress", 62, 480000, 301000, "Concrete mixer, Tower crane",
     [("cement", 420), ("steel", 18), ("brick", 22000)]),
    ("P2", "Mutare-Nyanga Access Road", "Manicaland", "in-progress", 35, 1250000, 410000, "Grader, Road roller",
     [("agg", 3200), ("diesel", 14000)]),
    ("P3", "Ruwa Housing Phase 2", "Ruwa", "not-started", 0, 620000, 0, "Concrete mixer, Scaffolding",
     [("cement", 900), ("brick", 65000), ("steel", 30)]),
    ("P4", "Msasa Warehouse Upgrade", "Harare", "complete", 100, 210000, 198000, "", []),
    ("P5", "Bindura Bridge Rehabilitation", "Mashonaland Central", "in-progress", 78, 340000, 290000, "Excavator",
     [("steel", 12), ("sand", 450)]),
    ("P6", "Norton Retail Complex", "Norton", "not-started", 0, 530000, 0, "Tower crane, Concrete mixer",
     [("brick", 48000)]),
]

SEED_ACCOUNTS_DATA = [
    ("Ian Admin", "admin@leengate.co.zw", "admin", None),
    ("Pat Procurement", "procurement@leengate.co.zw", "procurement", None),
    ("Pam Projects", "pm@leengate.co.zw", "pm", None),
    ("Faith Finance", "finance@leengate.co.zw", "finance", None),
    ("Sam Site-Engineer", "engineer@leengate.co.zw", "engineer", None),
    ("Steve Steelmate", "supplier.steelmate@leengate.co.zw", "supplier", "B"),
    ("Paula PPC", "supplier.ppc@leengate.co.zw", "supplier", "A"),
]


def _month_of(latest: date, back: int) -> int:
    idx = latest.year * 12 + latest.month - 1 - back
    return idx % 12 + 1


def ensure_accounts(db, seed_password="12345simba", admin_password="nyasimba"):
    """Run on EVERY start-up. Makes sure each demo account exists, is active, is unlocked and
    has the configured password - so an old database file (made with an older password, or
    with an account locked by mistyped passwords) can never leave you unable to sign in."""
    from werkzeug.security import check_password_hash
    from .db import User
    for name, email, role, sup in SEED_ACCOUNTS_DATA:
        pw = admin_password if role == "admin" else seed_password
        u = db.query(User).filter(User.email == email).one_or_none()
        if u is None:
            db.add(User(name=name, email=email, password_hash=hash_password(pw), role=role,
                        supplier_id=sup, status="active"))
            continue
        if not check_password_hash(u.password_hash, pw):
            u.password_hash = hash_password(pw)
        u.status, u.failed_logins, u.locked_until = "active", 0, None
    db.commit()


def seed(db, seed_accounts=True, seed_password="12345simba", admin_password="nyasimba", today=None):
    if db.query(Supplier).count():
        return False                                    # already seeded
    today = today or date.today()
    rng = np.random.default_rng(42)

    for s in SUPPLIERS:
        db.add(Supplier(id=s[0], name=s[1], category=s[2], city=s[3], reliability=s[4], ontime=s[5],
                        lead_days=s[6], defect_rate=s[7], cost_index=s[8], risk=s[9], capacity=s[10],
                        capacity_unit=s[11]))
    db.flush()

    for mid, name, unit, base, g, amp, noise, lead, cost, sup, ratio in MATERIALS:
        series = []
        for t in range(36):
            month = _month_of(today, 35 - t)
            v = base * (1 + g * t) * (1 + amp * math.sin(2 * math.pi * (month - 5) / 12)) \
                * (1 + (rng.random() - .5) * 2 * noise)
            series.append(round(v))
            db.add(MonthlyDemand(material_id=mid, period=t, month=month, quantity=series[-1]))
        monthly = float(np.mean(series[-12:]))
        rop = monthly / 30 * lead * 1.25
        db.add(Material(id=mid, name=name, unit=unit, unit_cost=cost, lead_days=lead, supplier_id=sup,
                        stock=round(rop * ratio, 1), reorder_point=round(rop, 1)))
    db.flush()

    supplier_risk = {s[0]: s[9] for s in SUPPLIERS}
    for rid, name, sup, days, base in ROUTES:
        db.add(Route(id=rid, name=name, supplier_id=sup, transit_days=days, base_delay_rate=base))
        for t in range(36):
            month = _month_of(today, 35 - t)
            for _ in range(4):
                p = min(.9, base * (1 + .8 * supplier_risk[sup] / 100) * (1 + .3 * math.sin(2 * math.pi * month / 12)))
                late = int(rng.random() < p)
                actual = max(.5, days + (rng.integers(1, 5) if late else rng.integers(-1, 1) * .3))
                db.add(Shipment(route_id=rid, period=t, month=month, planned_days=days,
                                actual_days=round(float(actual), 2), delayed=late))

    for pid, name, loc, status, prog, budget, spent, equip, needs in PROJECTS:
        db.add(Project(id=pid, name=name, location=loc, status=status, progress=prog, budget=budget,
                       spent=spent, equipment=equip, needs=[ProjectNeed(material_id=m, quantity=q) for m, q in needs]))

    if seed_accounts:
        for name, email, role, sup in SEED_ACCOUNTS_DATA:
            db.add(User(name=name, email=email, password_hash=hash_password(admin_password if role == "admin" else seed_password), role=role,
                        supplier_id=sup, status="active"))
    db.commit()
    return True
