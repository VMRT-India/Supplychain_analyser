# SupplyChain Analyzer

A production-grade supply chain provenance and ethical tracking system. It traces every product from raw material to final batch, enforces supplier compliance, processes IoT environmental data, and provides role-gated dashboards for Admins, Auditors, Suppliers, and Consumers.

---

## Run Locally

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Start the backend
uvicorn main:app --reload

# 3. Open any HTML file directly in your browser
open login.html
```

> The database must be running. See database setup below if starting fresh.

### Database Setup (first time only)

```bash
# Create the database and seed it
psql -U postgres -c "CREATE DATABASE supplychain_analyzer;"
psql -U postgres -d supplychain_analyzer -f database.sql
```

---

## Run with Docker

```bash
docker compose up --build
```

Both services start automatically. The database is seeded on first run.  
API available at `http://localhost:8000`. Open HTML files directly in your browser.

### Reset everything

```bash
docker compose down -v && docker compose up --build
```

---

## API Endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/health` | Any | Check if server and DB are alive |
| `POST` | `/login` | Any | Verify password → JWT (Supplier/Consumer) or MFA gate (Admin/Auditor) |
| `POST` | `/verify-mfa` | Admin/Auditor | Validate TOTP code → JWT |
| `POST` | `/setup-mfa` | Admin/Auditor | Generate TOTP secret and return provisioning URI |
| `POST` | `/register` | Any | Create account; Supplier role also seeds the suppliers table |
| `POST` | `/create-batch` | Supplier | Register a new component batch (blocked at DB level if supplier is Violated) |
| `GET` | `/score/{component_id}` | Any | Recursive ethical score from materialized view `component_scores_mv` |
| `GET` | `/qr/{uuid}` | Any | Generate PNG QR code for a batch UUID encoding its product URL |
| `POST` | `/refresh-scores` | Admin | Refresh materialized view `component_scores_mv` concurrently |
| `POST` | `/iot-data` | Supplier | Submit temperature + humidity; flags violation and deducts score if temp > 50 |
| `GET` | `/product/{batch_id}` | Consumer | Full product provenance: batch UUID, score, violations, audit trail |
| `GET` | `/supplier/{supplier_id}/status` | Auditor | Returns supplier company name and compliance status |
| `POST` | `/issue-certificate` | Auditor | Issue an ethical certificate for a batch |
| `POST` | `/approve-supplier` | Admin | Set supplier compliance to `Compliant` or `Violated`; recalculates scores |
| `POST` | `/metrics` | Supplier | Submit a named ethical metric for a component (e.g. `carbon_footprint`) |
| `GET` | `/metrics/{component_id}` | Any | Retrieve all ethical metrics for a component |
| `GET` | `/audit-logs` | Admin/Auditor | Filterable audit log; query by `batch_id`, `event_category`, `limit` |

---

## Test Credentials

| Role | Email | Password | Notes |
|------|-------|----------|-------|
| Admin | `admin@test.com` | `123` | Full access; MFA second step required (TOTP) |
| Auditor | `auditor@test.com` | `123` | Score, supplier status, certificates, audit logs; MFA required |
| Supplier | `supplier1@test.com` | `123` | Steel Corp — Compliant (supplier_id: 3) |
| Supplier | `supplier2@test.com` | `123` | Mining Ltd — Violated (supplier_id: 4) |
| Supplier | `supplier3@test.com` | `123` | Textile Works — Compliant (supplier_id: 5) |
| Consumer | `consumer@test.com` | `123` | Read-only product view |

### Useful seed data IDs

| Entity | ID | Description |
|--------|----|-------------|
| Batch | 1 | Steel batch (supplier: Steel Corp) |
| Batch | 2 | Fabric batch (supplier: Textile Works) |
| Batch | 3 | Car Body batch |
| Batch | 4 | T-Shirt batch |
| Component | 1 | Iron Ore (root) |
| Component | 4 | Steel (child of Iron Ore) |
| Component | 6 | Car Body (child of Steel) |

---

## Run Tests

```bash
# Activate venv first
source .venv/bin/activate

# Run all tests
pytest test_main.py -v
```

> Tests require the local database to be running. All 7 tests hit the live DB — no mocks.
