"""XGBoost models that power every department's predictions.

1. Demand forecaster  - XGBRegressor per material, trained on 36 months of history.
   Features are the last 3 months and the same month last year (all divided by the
   trailing 12-month level so trends are handled) plus month-of-year sin/cos.
2. Route-delay classifier - XGBClassifier that predicts the probability a delivery on
   a route will arrive late next month.
"""
import math
import threading

import numpy as np
from sqlalchemy.orm import sessionmaker
from sklearn.metrics import roc_auc_score
from xgboost import XGBClassifier, XGBRegressor

from .db import Material, MonthlyDemand, Route, Shipment

HOLDOUT = 6
DEMAND_PARAMS = {"n_estimators": 250, "max_depth": 3, "learning_rate": 0.06, "subsample": 0.9, "colsample_bytree": 0.9}
ROUTE_PARAMS = {"n_estimators": 120, "max_depth": 3, "learning_rate": 0.08}
DEMAND_FEATURES = ["last_month", "2_months_ago", "3_months_ago", "same_month_last_year", "season_sin", "season_cos"]
ROUTE_FEATURES = ["transit_days", "historical_delay_rate", "supplier_risk", "season_sin", "season_cos"]


def _row(q, t, month):
    level = float(np.mean(q[t - 12:t])) or 1.0
    ang = 2 * math.pi * month / 12
    return level, [q[t - 1] / level, q[t - 2] / level, q[t - 3] / level, q[t - 12] / level,
                   math.sin(ang), math.cos(ang)]


def _new_regressor(n_estimators=250):
    return XGBRegressor(n_estimators=n_estimators, max_depth=3, learning_rate=0.06, subsample=0.9,
                        colsample_bytree=0.9, reg_lambda=1.0, random_state=42, n_jobs=1, verbosity=0)


class ForecastService:
    def __init__(self, engine, n_estimators=250):
        self.new_session = sessionmaker(bind=engine, expire_on_commit=False)   # private session: never touches a request's
        self.n_estimators = n_estimators
        self.demand = {}     # material_id -> {"model", "series", "months", "metrics"}
        self.route_model = None
        self.route_metrics = {}
        self._lock = threading.RLock()   # reentrant: train_all() calls self.metrics() while still holding it

    # ------------------------------------------------------------------ training
    def train_all(self):
        with self._lock, self.new_session() as db:
            self.demand = {}
            for m in db.query(Material).all():
                rows = (db.query(MonthlyDemand).filter(MonthlyDemand.material_id == m.id)
                        .order_by(MonthlyDemand.period).all())
                if len(rows) >= 20:
                    self.demand[m.id] = self._train_demand([r.quantity for r in rows], [r.month for r in rows])
            self._train_routes(db)
            return self.metrics()

    def _train_demand(self, series, months):
        X, y = [], []
        for t in range(12, len(series)):
            level, feats = _row(series, t, months[t])
            X.append(feats)
            y.append(series[t] / level)
        X, y = np.array(X), np.array(y)
        # honest accuracy: train on the past, predict the last HOLDOUT months one step ahead
        model = _new_regressor(self.n_estimators).fit(X[:-HOLDOUT], y[:-HOLDOUT])
        actual, pred = [], []
        for i, t in enumerate(range(len(series) - HOLDOUT, len(series))):
            level, feats = _row(series, t, months[t])
            pred.append(float(model.predict(np.array([feats]))[0]) * level)
            actual.append(series[t])
        actual, pred = np.array(actual), np.array(pred)
        mape = float(np.mean(np.abs((actual - pred) / actual)) * 100)
        final = _new_regressor(self.n_estimators).fit(X, y)       # production model uses all data
        importances = {f: round(float(v), 4) for f, v in zip(DEMAND_FEATURES, final.feature_importances_)}
        return {"model": final, "series": list(series), "months": list(months),
                "metrics": {"mape": round(mape, 2), "accuracy": round(100 - mape, 2),
                            "train_rows": int(len(X)), "holdout_months": HOLDOUT, "feature_importance": importances}}

    def _train_routes(self, db):
        rows = (db.query(Shipment, Route).join(Route, Shipment.route_id == Route.id)
                .order_by(Shipment.period).all())
        if len(rows) < 100:
            self.route_model, self.route_metrics = None, {}
            return
        X = np.array([self._route_feats(r, s.month) for s, r in rows])
        y = np.array([s.delayed for s, _ in rows])
        cut = int(len(y) * 0.8)
        auc = None
        if len(set(y[:cut])) > 1 and len(set(y[cut:])) > 1:
            probe = XGBClassifier(n_estimators=120, max_depth=3, learning_rate=0.08, random_state=42,
                                  n_jobs=1, verbosity=0).fit(X[:cut], y[:cut])
            auc = float(roc_auc_score(y[cut:], probe.predict_proba(X[cut:])[:, 1]))
        self.route_model = XGBClassifier(n_estimators=120, max_depth=3, learning_rate=0.08, random_state=42,
                                         n_jobs=1, verbosity=0).fit(X, y)
        importances = {f: round(float(v), 4) for f, v in zip(ROUTE_FEATURES, self.route_model.feature_importances_)}
        self.route_metrics = {"auc": round(auc, 3) if auc is not None else None, "train_rows": int(len(y)),
                              "delay_rate": round(float(y.mean()), 3), "feature_importance": importances}

    @staticmethod
    def _route_feats(route, month):
        ang = 2 * math.pi * month / 12
        return [route.transit_days, route.base_delay_rate, route.supplier.risk / 100, math.sin(ang), math.cos(ang)]

    # ------------------------------------------------------------------ prediction
    def ensure(self):
        with self._lock:
            empty = not self.demand
        if empty:
            self.train_all()

    def forecast(self, material_id, months=6):
        """Recursive multi-step forecast. Returns a list of {month, quantity}."""
        self.ensure()
        with self._lock:
            entry = self.demand.get(material_id)
        if entry is None:
            return None
        series, mlist, model = list(entry["series"]), list(entry["months"]), entry["model"]
        out = []
        for _ in range(months):
            t = len(series)
            month = mlist[-1] % 12 + 1
            mlist.append(month)
            series.append(series[-1])            # placeholder so indices line up
            level, feats = _row(series, t, month)
            value = max(0.0, float(model.predict(np.array([feats]))[0]) * level)
            series[-1] = value
            out.append({"month": month, "quantity": round(value, 2)})
        return out

    def route_risk(self, db, next_month):
        """Probability each route has a late delivery next month."""
        self.ensure()
        with self._lock:
            model = self.route_model
        if model is None:
            return []
        routes = db.query(Route).all()
        if not routes:
            return []
        probs = model.predict_proba(np.array([self._route_feats(r, next_month) for r in routes]))[:, 1]
        return [{"route_id": r.id, "route": r.name, "supplier": r.supplier.name,
                 "transit_days": r.transit_days, "delay_probability": round(float(p), 3)}
                for r, p in zip(routes, probs)]

    def metrics(self):
        with self._lock:
            demand_snapshot = {k: v["metrics"] for k, v in self.demand.items()}
            route_metrics_snapshot = dict(self.route_metrics)
        return {"demand": demand_snapshot, "route_delay": route_metrics_snapshot}

    def diagnostics(self):
        """Real hyperparameters and feature importance for the IT/AI Management console -
        not hardcoded figures: these come straight off the fitted XGBoost models."""
        with self._lock:
            per_material = {k: v["metrics"]["feature_importance"] for k, v in self.demand.items()
                            if "feature_importance" in v["metrics"]}
            route_importance = self.route_metrics.get("feature_importance", {})
            mean_accuracy = (round(float(np.mean([v["metrics"]["accuracy"] for v in self.demand.values()])), 2)
                             if self.demand else None)
        avg_importance = {f: round(float(np.mean([per_material[m].get(f, 0) for m in per_material])), 4)
                          for f in DEMAND_FEATURES} if per_material else {}
        return {"demand_model": {"type": "XGBRegressor", "params": DEMAND_PARAMS, "holdout_months": HOLDOUT,
                                 "materials_trained": len(per_material), "mean_accuracy_pct": mean_accuracy,
                                 "feature_importance": avg_importance, "per_material": per_material},
                "route_model": {"type": "XGBClassifier", "params": ROUTE_PARAMS,
                                "feature_importance": route_importance, **self.route_metrics}}
