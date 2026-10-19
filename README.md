# Leengate AI Supply Chain Optimisation Platform

AI-driven supply chain optimisation for construction, built around a real case study at
Leengate Construction & Plant Hire (Harare, Zimbabwe). Flask + SQLAlchemy + XGBoost
backend, a single-page frontend with role-based dashboards for six departments, and a
SQL database hardened against injection and seeded with real supplier companies.

## Architecture
```
final_project/
  backend/     Flask app: config, database models, security, XGBoost, API routes
  frontend/    The platform UI - one HTML file, served by Flask and signed in against the API
  tests/       48 automated tests (pytest) - auth, RBAC, SQL injection, XGBoost
  instance/    SQLite database file, created here on first run (git-ignored)
  run.py       Entry point: python run.py
```

The frontend signs in against the real backend and loads its data from it - it is not a
standalone demo file. Always run it via `python run.py` and open it at
**http://127.0.0.1:5000**; opening the HTML file directly, with no server, will show the
landing page but cannot sign in, since the sign-in form calls `/api/auth/login` on
whatever origin served the page.

On sign-in, the browser calls `/api/auth/login`, then fetches `/api/materials` (with
36-month history per material), `/api/inventory`, `/api/suppliers` (or
`/api/suppliers/me` for a Supplier account), `/api/route-risk`, `/api/projects`,
`/api/item-requests`, `/api/records` and `/api/forecast-summary` in parallel, and merges
the results into the dashboards - so every number on Command Centre, Inventory,
Suppliers, Projects, Finance and Data Intelligence comes from the database and the
XGBoost models. Adding a record, requesting items, approving a user, retraining the
models and running the integrity check are all real `POST`/`PATCH`/`DELETE` calls
against the API.

Two parts are intentionally client-side, and stay labelled "Simulated" in the UI: the
**AI Model Lab** page's side-by-side comparison of five model types (the backend trains
XGBoost specifically, matching the model the dissertation evaluates and recommends, so
there is no server equivalent for the other four comparison models), and the **Data
Intelligence** page's "before/after cleaning" illustration, which works on a separately
generated messy dataset to show the cleaning pipeline rather than Leengate's actual
(already-clean) records.

## Departments and access control
Six roles, each seeing only their own department's data - enforced on the server, not
just hidden in the browser menu:

| Role | Sees |
|---|---|
| Supplier | Their own company's performance, capacity and demand forecast only |
| Procurement | All suppliers, inventory, forecasting, data records, recommendations |
| Project Management | Every project, its status, equipment and materials needed; can request items |
| Finance | Budgets, funding needed, AI-predicted procurement cost |
| Site Engineer | Stock levels, manual data entry, delay alerts |
| IT / AI Management | Everything, plus user approval, audit log, model retraining, data-integrity checks |

Accounts are provisioned by the IT / AI Management team; there is no public "request access" form
and no self-registration.

## Security
- Passwords are hashed with `werkzeug.security` (scrypt + a random salt per user) -
  nothing is ever stored or compared in plain text.
- Sessions are server-side: a random 32-byte token is issued, only its SHA-256 hash is
  stored, and signing out deletes that row, so the old cookie is provably dead afterwards
  (`test_old_cookie_cannot_be_replayed_after_logout`).
- Every response carries `Cache-Control: no-store`, `Pragma: no-cache` and, on logout,
  `Clear-Site-Data`, so the browser itself is told to drop anything cached for the site -
  pressing "back" after signing out cannot bring a previous session's dashboard back.
- 5 wrong passwords locks the account for 15 minutes; the error message is identical for
  "wrong password" and "no such account", so the login form cannot be used to discover
  who has an account.
- All database queries go through SQLAlchemy's ORM, which sends every value as a bound
  parameter - user input is never pasted into a SQL string. `tests/test_security.py`
  throws 9 different SQL-injection payloads at the login form, query-string filters and
  JSON bodies, and checks the database is untouched afterwards. A source-scanner test
  fails the build if anyone ever writes string-built SQL into the codebase.
- The schema itself rejects bad data even if application code has a bug: `CHECK`
  constraints, `FOREIGN KEY`s (`PRAGMA foreign_keys=ON`) and `UNIQUE` constraints are
  enforced by SQLite directly.
- The audit log is append-only - database triggers block `UPDATE`/`DELETE` on it, so even
  a compromised admin session cannot quietly rewrite history.

## XGBoost
- `XGBRegressor`, one per material, forecasts next month's demand from 36 months of
  history (lag features plus month-of-year seasonality), evaluated on a 6-month holdout
  so the accuracy shown in the UI is measured, not asserted.
- `XGBClassifier` predicts the probability each delivery route is late next month, from
  transit time, historical delay rate and the supplier's risk score.
- These two models drive `/api/forecast/<material>`, `/api/alerts` (low stock and
  delayed-route warnings), `/api/forecast-summary` (predicted procurement cost), and the
  Supplier and Projects pages' predictions.
- `/api/admin/retrain` lets IT/AI Management retrain both models on demand;
  `/api/admin/integrity` reports data-integrity, validation and model-health checks in
  one place - the non-functional requirements (data integrity, validation, scalability,
  adaptability, maintainability) that role is responsible for; `/api/admin/diagnostics`
  reports each model's real hyperparameters and feature importance, read directly off
  the fitted XGBoost objects (`model.feature_importances_`) rather than hardcoded -
  `test_model_diagnostics_are_real_not_hardcoded` checks the importances actually sum to
  ~1 and are admin-only.

## Running it
```bash
cd final_project
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```
Open **http://127.0.0.1:5000**. The database - 8 real Zimbabwean supplier companies, 6
materials with 36 months of history, 5 delivery routes, 6 Leengate projects and 7 seed
accounts - is created automatically on first run, in `instance/leengate.db`.

Copy `.env.example` to `.env` (or export the same variables) to change the database URL,
the seed-account password, or turn off account seeding for a real deployment. Set
`LEENGATE_COOKIE_SECURE=1` once the site is served over HTTPS.

### Seed accounts
One account per department. Passwords are NOT shown on the sign-in screen; they are in
`docs/Leengate_Login_Credentials.docx`. Every account uses `12345simba`, except the admin
account (`nyasimba`). Override with `LEENGATE_SEED_PASSWORD` / `LEENGATE_ADMIN_PASSWORD`.
On every start-up the server re-applies these passwords and unlocks the accounts, so an old
database can no longer block sign-in.

| Email | Role |
|---|---|
| admin@leengate.co.zw | IT / AI Management |
| procurement@leengate.co.zw | Procurement |
| pm@leengate.co.zw | Project Management |
| finance@leengate.co.zw | Finance |
| engineer@leengate.co.zw | Site Engineer |
| supplier.steelmate@leengate.co.zw | Supplier (Steelmate) |
| supplier.ppc@leengate.co.zw | Supplier (PPC Zimbabwe) |

## Tests
```bash
pytest -q
```
45 tests covering login/logout/session behaviour, account lockout, rate limiting, CSRF,
the sign-up-then-admin-approval flow, role-based access for all six roles, SQL-injection
resistance, database-constraint enforcement, the audit trail's append-only guarantee, and
the XGBoost forecast/alerts/finance endpoints.

## Design
The dashboards use a construction-themed palette: Industrial Slate background
(`#121824`), Construction Gold as the primary accent (`#FFB800`), Safety Orange for
critical/high-risk states (`#FF5722`), and Dark Cyan as the secondary accent (`#0D9488`).
The landing and sign-in pages keep a separate purple-to-coral gradient hero treatment for
first impressions - a loud gradient behind a dashboard's dense tables would hurt
readability rather than help it, so the two live side by side rather than one theme
forcing a compromise on the other.

The Digital Twin page has a second map, alongside the existing supply-chain diagram:
toggle "Zimbabwe route map" under Layers to see Kwekwe (HQ), Harare, Bulawayo, Gweru,
Kadoma and Beitbridge laid out by their real relative geography, with animated trucks
running the road corridors between them. It is a stylised layout, not a georeferenced
map (no GIS library is involved) - accurate enough to recognise, not accurate enough to
measure distances from.

The layout is responsive down to phone width - grids collapse to one or two columns,
the sidebar becomes a toggleable drawer, and the 3D scenes resize to their container.

## Deliberately out of scope
A few feature ideas worth naming for the dissertation's "future work" section rather than
building unsafely under time pressure: multi-currency USD/ZiG conversion, PDF
Bill-of-Quantities parsing, mobile-money payout integration, an offline-first PWA sync
layer, and a cross-site circular-materials marketplace. Each is a real, independent
feature area - building all of them well needs its own design and test cycle, not an
afternoon bolted onto an already-working system two weeks before a presentation.

## Supplier data note
Supplier names (PPC Zimbabwe, Steelmate, Davis Granite, Willdale Limited, Zuva Petroleum,
Powerspeed Electrical, Turnall Holdings, Zimplow Holdings) are real Zimbabwean
construction-material businesses, used for realism in this academic study. Their
reliability, risk, defect-rate and capacity figures are illustrative example data for the
study, not a real performance assessment of those companies.
