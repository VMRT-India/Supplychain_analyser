# SupplyChain Analyzer — Architecture

---

## File Structure

```
supplychain_analyser/
│
├── main.py               FastAPI application — all endpoints, security, helpers, background tasks
├── database.sql          PostgreSQL schema, seed data, trigger, materialized view
├── requirements.txt      Python dependencies (FastAPI, SQLAlchemy, bcrypt, jose, pyotp, qrcode, etc.)
├── Dockerfile            Container build config — Python 3.12-slim base image
├── docker-compose.yml    Multi-container setup: app (:8000) + PostgreSQL 18
│
├── index.html            Homepage — landing page with feature overview, role descriptions, and nav links
├── login.html            Login page — email/password form, JWT storage, MFA second-step for Admin/Auditor
├── register.html         Registration page — new user creation, auto-seeds suppliers table
├── dashboard.html        Role-gated dashboard — all role-specific feature interactions
│
├── test_main.py          Integration and unit tests
├── architecture.md       This file — system structure, data flow, endpoint reference
├── project_context.md    System specification and instruction contract
└── README.md             Project documentation
```

---

## System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          FRONTEND  (Browser)                             │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │
│  │   login.html     │  │  register.html   │  │    dashboard.html      │ │
│  │                  │  │                  │  │                        │ │
│  │ Email + Password │  │ Name, Email,     │  │ Role-gated sidebar     │ │
│  │ → POST /login    │  │ Password, Role   │  │ (JWT in sessionStorage) │ │
│  │                  │  │ → POST /register │  │                        │ │
│  │ Admin/Auditor:   │  │                  │  │  Supplier → batch,iot  │ │
│  │   MFA code step  │  │ Supplier also    │  │            metrics     │ │
│  │ → POST /verify-  │  │   seeds          │  │  Auditor  → score,     │ │
│  │   mfa            │  │   suppliers      │  │            supplier,   │ │
│  │                  │  │   table          │  │            certificate,│ │
│  │ Stores JWT token │  │                  │  │            audit-logs  │ │
│  │ → redirect       │  │                  │  │  Admin    → all +      │ │
│  │   dashboard      │  │                  │  │            approve,    │ │
│  └────────┬─────────┘  └────────┬─────────┘  │            refresh-   │ │
│           │                     │             │            scores     │ │
│           └─────────────────────┴─────────────┤  Consumer → product, │ │
│                                               │            qr scan   │ │
│                                               │                        │ │
│                                               │  API calls:            │ │
│                                               │  POST /login           │ │
│                                               │  POST /verify-mfa      │ │
│                                               │  POST /setup-mfa       │ │
│                                               │  POST /register        │ │
│                                               │  POST /create-batch    │ │
│                                               │  GET  /score/{id}      │ │
│                                               │  POST /iot-data        │ │
│                                               │  GET  /product/{id}    │ │
│                                               │  GET  /qr/{uuid}       │ │
│                                               │  GET  /supplier/{id}/  │ │
│                                               │       status           │ │
│                                               │  POST /approve-        │ │
│                                               │       supplier         │ │
│                                               │  POST /issue-          │ │
│                                               │       certificate      │ │
│                                               │  POST /refresh-scores  │ │
│                                               │  POST /metrics         │ │
│                                               │  GET  /metrics/{id}    │ │
│                                               │  GET  /audit-logs      │ │
│                                               │  GET  /health          │ │
│                                               └──────────┬─────────────┘ │
└──────────────────────────────────────────────────────────┼───────────────┘
                                                           │
                              HTTP REST / JSON             │
                              Bearer token required        │
                              on all protected endpoints   │
                                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      BACKEND  (FastAPI + Uvicorn :8000)                  │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Security Layer                                                     │ │
│  │  bcrypt          Hash passwords at register; verify at login        │ │
│  │  JWT (HS256)     Signed token returned on login / MFA verify        │ │
│  │  verify_token()  HTTPBearer dependency — enforced on every          │ │
│  │                  protected endpoint at backend level                │ │
│  │  TOTP (pyotp)    Admin/Auditor: MFA setup via /setup-mfa,          │ │
│  │                  second-step verify via /verify-mfa                 │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Auth & User Management                                             │ │
│  │  POST /login          Verify bcrypt hash → JWT (or MFA gate)       │ │
│  │  POST /verify-mfa     Validate TOTP code → JWT                     │ │
│  │  POST /setup-mfa      Generate + store TOTP secret, return URI      │ │
│  │  POST /register       Hash password → insert user; if Supplier      │ │
│  │                       also inserts suppliers row                    │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Provenance Engine                                                  │ │
│  │  POST /create-batch   Compliance check → insert component + batch  │ │
│  │                       Returns batch_id + batch_uuid (UUID)         │ │
│  │  GET  /score/{id}     Read from materialized view                  │ │
│  │                       component_scores_mv (pre-computed recursive  │ │
│  │                       CTE) — single indexed lookup, no live CTE    │ │
│  │  GET  /qr/{uuid}      Lookup batch by UUID → generate PNG QR code │ │
│  │                       encoding /product/{batch_id} URL             │ │
│  │  POST /refresh-scores Admin-only → REFRESH MATERIALIZED VIEW       │ │
│  │                       CONCURRENTLY component_scores_mv             │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  IoT Processing                                                     │ │
│  │  POST /iot-data       Accept sensor_id + temperature + humidity    │ │
│  │                       Insert reading; if temp > 50 → flag          │ │
│  │                       violation; score deduction queued as         │ │
│  │                       background task (non-blocking response)      │ │
│  │                       Note: multi-param decision tree planned      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Compliance Module                                                  │ │
│  │  GET  /supplier/{id}/status   Return company + compliance_status   │ │
│  │  POST /approve-supplier       Admin sets Compliant / Violated →    │ │
│  │                               DB trigger also enforces at insert   │ │
│  │                               Score recalculation queued as        │ │
│  │                               background task                      │ │
│  │                               Violated: hard-set scores to 0       │ │
│  │                               Compliant: restore only scores = 0   │ │
│  │                               (preserves IoT-reduced values)       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Audit & Certificates                                               │ │
│  │  POST /issue-certificate    Auditor issues cert → audit_logs entry │ │
│  │  GET  /product/{batch_id}   Full provenance: batch_uuid, score,    │ │
│  │                             violations, audit logs                 │ │
│  │  GET  /audit-logs           Admin/Auditor only; filterable by      │ │
│  │                             batch_id, event_category, limit        │ │
│  │                             Categories: BATCH, IOT, COMPLIANCE,    │ │
│  │                             CERTIFICATE, AUTH, SYSTEM              │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Ethical Metrics                                                    │ │
│  │  POST /metrics              Supplier submits named metric for a    │ │
│  │                             component (e.g. carbon_footprint,      │ │
│  │                             worker_safety_score). Extensible —     │ │
│  │                             no schema change per new metric type   │ │
│  │  GET  /metrics/{id}         Retrieve all metrics for a component   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  System                                                             │ │
│  │  GET /health           Ping DB → {"status":"ok","db":"connected"}  │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  Helper functions                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐   │
│  │ calculate_recursive_score(db, id)          Live CTE (fallback)    │   │
│  │ recalculate_score_on_violation(db, batch)  Deduct 5, floor 0      │   │
│  │ recalculate_scores_for_supplier(db, s, c)  0 on Violated;         │   │
│  │                                            restore 0→10 on        │   │
│  │                                            Compliant only         │   │
│  │ log_event(db, batch_id, event,             Append-only audit log  │   │
│  │           category, triggered_by)          with category + actor  │   │
│  │ bg_recalculate_score_on_violation(batch)   Background wrapper     │   │
│  │ bg_recalculate_scores_for_supplier(s,c,a)  Background wrapper     │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Background Tasks (FastAPI BackgroundTasks)                              │
│  Score recalculation runs after response is sent.                        │
│  Each task opens its own DB session independently.                       │
│                                                                          │
│                           SQLAlchemy ORM                                 │
└─────────────────────────────────────────────────────────────┬────────────┘
                                                              │
                                                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       DATABASE  (PostgreSQL 18)                          │
│                                                                          │
│  ┌─────────────────────────┐     ┌──────────────────────────────────┐   │
│  │         users           │     │           components             │   │
│  │─────────────────────────│     │──────────────────────────────────│   │
│  │ user_id     (PK)        │     │ component_id  (PK)               │   │
│  │ name                    │     │ name                             │   │
│  │ email        UNIQUE     │     │ parent_id  ──────────────────────┼─┐ │
│  │ password     bcrypt     │     │ ethical_score  (default 10)      │ │ │
│  │ role                    │     └──────────────────────────────────┘ │ │
│  │ mfa_secret   TOTP key   │              ▲ self-referencing tree     │ │
│  └────────────┬────────────┘              └───────────────────────────┘ │
│               │ 1:1                                                      │
│               ▼                                                          │
│  ┌─────────────────────────┐     ┌──────────────────────────────────┐   │
│  │        suppliers        │     │             batches              │   │
│  │─────────────────────────│     │──────────────────────────────────│   │
│  │ supplier_id (FK→users)  │────▶│ batch_id       (PK)              │   │
│  │ company_name            │     │ batch_uuid     UUID  UNIQUE      │   │
│  │ compliance_status       │     │ component_id   (FK → components) │   │
│  └─────────────────────────┘     │ supplier_id    (FK → suppliers)  │   │
│                                  │ quantity                         │   │
│                                  │ status                           │   │
│                                  └───────┬──────────────────────────┘   │
│                                          │                               │
│          ┌───────────────────────────────┼────────────────────┐         │
│          ▼                               ▼                     ▼         │
│  ┌──────────────────┐   ┌─────────────────────┐  ┌────────────────────┐ │
│  │   iot_readings   │   │     audit_logs      │  │ethical_certificates│ │
│  │──────────────────│   │─────────────────────│  │────────────────────│ │
│  │ reading_id  (PK) │   │ log_id       (PK)   │  │ certificate_id(PK) │ │
│  │ batch_id    (FK) │   │ batch_id     (FK)   │  │ batch_id      (FK) │ │
│  │ sensor_id        │   │ event               │  │ issued_by     (FK) │ │
│  │ temperature      │   │ event_category      │  │ notes              │ │
│  │ humidity         │   │ triggered_by  (FK)  │  │ issued_at          │ │
│  │ is_violation     │   │ timestamp           │  └────────────────────┘ │
│  │ timestamp        │   └─────────────────────┘                         │
│  └──────────────────┘                                                    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  ethical_metrics                                                 │    │
│  │  metric_id (PK) │ component_id (FK) │ metric_name │ metric_value │    │
│  │  recorded_by (FK → users) │ recorded_at                         │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  MATERIALIZED VIEW: component_scores_mv                          │    │
│  │  component_id (UNIQUE INDEX) │ total_score                       │    │
│  │  Pre-computed recursive SUM of ethical_score for every component │    │
│  │  Refreshed on demand via POST /refresh-scores (Admin only)       │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  TRIGGER: trg_check_supplier_compliance                          │    │
│  │  BEFORE INSERT ON batches                                        │    │
│  │  Raises EXCEPTION if supplier compliance_status = 'Violated'    │    │
│  │  Enforces compliance at DB level independent of app layer        │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Summary

```
User action in browser
        │
        ▼
Frontend JS (fetch) ──► POST/GET http://127.0.0.1:8000/<endpoint>
        │                       Authorization: Bearer <JWT token>
        │                                │
        │                                ▼
        │                        verify_token() validates JWT
        │                                │
        │                                ▼
        │                        FastAPI validates input
        │                                │
        │                                ▼
        │                        Business logic executes
        │                        (compliance check, score calc, etc.)
        │                                │
        │                                ▼
        │                        SQLAlchemy executes SQL
        │                        (DB trigger fires on INSERT if applicable)
        │                                │
        │                                ▼
        │                        PostgreSQL reads / writes
        │                                │
        │                                ▼
        │                        JSON response returned immediately
        │                                │
        │                                ▼
        │                Frontend displays result
        │
        │   Background (after response sent):
        └──► BackgroundTask opens own DB session
                        │
                        ▼
             Score recalculation / audit logging commits
```

---

## Authenticated Login Flow

```
POST /login
    │
    ├── Password verified via bcrypt
    │
    ├── Role = Supplier / Consumer
    │       └──► JWT returned immediately
    │
    └── Role = Admin / Auditor  AND  mfa_secret is set
            └──► { mfa_required: true, user_id }
                        │
                        ▼
               User enters TOTP code
                        │
                        ▼
               POST /verify-mfa
                        │
                        ▼
               JWT returned on success
```

---

## Recursive Score Tree Example

```
Iron Ore  (score: 10)
    └── Steel  (score: 20)
            └── Car Body  (score: 30)

GET /score/1  →  reads component_scores_mv  →  total = 60
GET /score/4  →  reads component_scores_mv  →  total = 50
GET /score/6  →  reads component_scores_mv  →  total = 30

POST /refresh-scores  →  REFRESH MATERIALIZED VIEW CONCURRENTLY
                         (Admin only, non-blocking, run after bulk updates)
```

---

## Deferred Items (Noted for Future Phases)

| Item | Note |
|---|---|
| Bug 7 — IoT multi-param validation | Decision tree planned to replace single threshold check |
| Feature 9 — Consumer feedback | Deferred |
| Feature 10 — Real-time alerting | Alerting system planned for a future phase |
