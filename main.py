import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import io
import bcrypt
import pyotp
import qrcode
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# =========================
# SECURITY CONFIG
# =========================
SECRET_KEY = os.environ.get("SECRET_KEY", "supplychain-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        role = payload.get("role")
        if user_id is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"user_id": user_id, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# =========================
# DATABASE CONFIG
# =========================
load_dotenv()
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:password@localhost/supplychain_analyzer")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# =========================
# APP INIT
# =========================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# =========================
# STARTUP — SEED MFA FOR ADMIN/AUDITOR
# =========================
@app.on_event("startup")
def seed_mfa_on_startup():
    db = SessionLocal()
    try:
        rows = db.execute(
            text("""
                SELECT user_id, name, email, role
                FROM users
                WHERE role IN ('Admin', 'Auditor')
                AND (mfa_secret IS NULL OR mfa_secret = '')
            """)
        ).fetchall()

        if not rows:
            print("[MFA] All Admin/Auditor accounts already have MFA configured.")
            return

        for user_id, name, email, role in rows:
            secret = pyotp.random_base32()
            db.execute(
                text("UPDATE users SET mfa_secret = :secret WHERE user_id = :id"),
                {"secret": secret, "id": user_id}
            )
            totp_uri = pyotp.TOTP(secret).provisioning_uri(
                name=email,
                issuer_name="SupplyChain Analyzer"
            )
            print(f"\n{'='*50}")
            print(f"[MFA SETUP] Role  : {role}")
            print(f"[MFA SETUP] Name  : {name}")
            print(f"[MFA SETUP] Email : {email}")
            print(f"[MFA SETUP] Secret: {secret}")
            print(f"[MFA SETUP] URI   : {totp_uri}")
            print(f"{'='*50}\n")

        db.commit()
        print("[MFA] Secrets seeded. Scan the URIs above into your authenticator app.")

    except Exception as e:
        db.rollback()
        print(f"[MFA] Startup seed failed: {e}")

    finally:
        db.close()

# =========================
# AUDIT LOG FUNCTION
# =========================
def log_event(db, batch_id, event, category="SYSTEM", triggered_by=None):
    db.execute(
        text("""
            INSERT INTO audit_logs (batch_id, event, event_category, triggered_by)
            VALUES (:batch_id, :event, :category, :triggered_by)
        """),
        {
            "batch_id":     batch_id,
            "event":        event,
            "category":     category,
            "triggered_by": triggered_by
        }
    )

# =========================
# RECURSIVE SCORE FUNCTION
# =========================
def calculate_recursive_score(db, component_id):
    result = db.execute(
        text("""
            WITH RECURSIVE component_tree AS (
                SELECT component_id, ethical_score
                FROM components
                WHERE component_id = :id

                UNION ALL

                SELECT c.component_id, c.ethical_score
                FROM components c
                INNER JOIN component_tree ct
                ON c.parent_id = ct.component_id
            )
            SELECT SUM(ethical_score) FROM component_tree
        """),
        {"id": component_id}
    ).fetchone()

    return result[0] if result[0] else 0

# =========================
# SCORE RECALCULATION
# =========================
def recalculate_score_on_violation(db, batch_id):
    """Deduct 5 from the ethical_score of the component linked to this batch. Floor: 0."""
    db.execute(
        text("""
            UPDATE components
            SET ethical_score = GREATEST(0, ethical_score - 5)
            WHERE component_id = (
                SELECT component_id FROM batches WHERE batch_id = :batch_id
            )
        """),
        {"batch_id": batch_id}
    )
    log_event(db, batch_id, "Ethical score recalculated due to IoT violation", category="IOT")

def recalculate_scores_for_supplier(db, supplier_id, compliance_status):
    """Adjust ethical_score for all components linked to a supplier's batches.
    Called when supplier compliance status changes.

    Violated  → hard-set to 0 (compliance enforcement).
    Compliant → restore schema default (10) ONLY for components currently at 0
                due to the supplier violation. Components with scores already
                reduced by IoT events (1–9) are left untouched to preserve
                those legitimate deductions.
    """
    if compliance_status == "Violated":
        db.execute(
            text("""
                UPDATE components
                SET ethical_score = 0
                WHERE component_id IN (
                    SELECT component_id FROM batches WHERE supplier_id = :supplier_id
                )
            """),
            {"supplier_id": supplier_id}
        )
    else:
        # Restore only scores that are exactly 0 (zeroed by the violation).
        # Scores between 1–9 were reduced by IoT events and must not be reset.
        db.execute(
            text("""
                UPDATE components
                SET ethical_score = 10
                WHERE ethical_score = 0
                  AND component_id IN (
                    SELECT component_id FROM batches WHERE supplier_id = :supplier_id
                  )
            """),
            {"supplier_id": supplier_id}
        )

# =========================
# BACKGROUND TASK WRAPPERS
# Each opens its own DB session — safe to run after response is sent.
# =========================
def bg_recalculate_score_on_violation(batch_id: int):
    db = SessionLocal()
    try:
        recalculate_score_on_violation(db, batch_id)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

def bg_recalculate_scores_for_supplier(supplier_id: int, compliance_status: str, admin_id: int):
    db = SessionLocal()
    try:
        recalculate_scores_for_supplier(db, supplier_id, compliance_status)
        batches = db.execute(
            text("SELECT batch_id FROM batches WHERE supplier_id = :id"),
            {"id": supplier_id}
        ).fetchall()
        for b in batches:
            log_event(db, b[0], f"Supplier compliance set to {compliance_status} by admin {admin_id}",
                      category="COMPLIANCE", triggered_by=admin_id)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

# =========================
# CREATE BATCH (UPDATED RESPONSE FORMAT)
# =========================
@app.post("/create-batch")
def create_batch(data: dict, token_data: dict = Depends(verify_token)):
    if token_data["role"] not in ("Supplier", "Admin"):
        raise HTTPException(status_code=403, detail="Only Suppliers can create batches")

    db = SessionLocal()

    try:
        supplier_id = int(data["supplier_id"])

        supplier_check = db.execute(
            text("SELECT supplier_id FROM suppliers WHERE supplier_id = :id"),
            {"id": supplier_id}
        ).fetchone()

        if not supplier_check:
            return {
                "success": False,
                "error": "Invalid supplier ID"
            }

        compliance = db.execute(
            text("SELECT compliance_status FROM suppliers WHERE supplier_id = :id"),
            {"id": supplier_id}
        ).fetchone()

        if compliance and compliance[0] == "Violated":
            return {
                "success": False,
                "error": "Batch creation blocked: supplier compliance status is Violated"
            }

        result = db.execute(
            text("INSERT INTO components (name) VALUES (:name) RETURNING component_id"),
            {"name": data["component_name"]}
        )
        component_id = result.fetchone()[0]

        batch_result = db.execute(
            text("""
                INSERT INTO batches (component_id, supplier_id, quantity)
                VALUES (:component_id, :supplier_id, :quantity)
                RETURNING batch_id, batch_uuid
            """),
            {
                "component_id": component_id,
                "supplier_id": supplier_id,
                "quantity": 100
            }
        )
        batch_row = batch_result.fetchone()
        batch_id = batch_row[0]
        batch_uuid = str(batch_row[1])

        log_event(db, batch_id, f"Batch created with supplier {supplier_id}",
                  category="BATCH", triggered_by=supplier_id)

        db.commit()

        return {
            "success": True,
            "data": {
                "message": "Batch created successfully",
                "batch_id": batch_id,
                "batch_uuid": batch_uuid
            }
        }

    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "error": str(e)
        }

    finally:
        db.close()

# =========================
# GET ETHICAL SCORE
# =========================
@app.get("/score/{component_id}")
def get_score(component_id: int):
    db = SessionLocal()

    try:
        result = db.execute(
            text("SELECT total_score FROM component_scores_mv WHERE component_id = :id"),
            {"id": component_id}
        ).fetchone()

        if not result:
            return {"score": "Not found"}

        return {"score": result[0]}

    except Exception as e:
        db.rollback()
        return {"score": None, "error": str(e)}

    finally:
        db.close()

# =========================
# IOT DATA
# =========================
@app.post("/iot-data")
def iot_data(data: dict, background_tasks: BackgroundTasks, token_data: dict = Depends(verify_token)):
    if token_data["role"] not in ("Supplier", "Admin"):
        raise HTTPException(status_code=403, detail="Only Suppliers can submit IoT data")

    db = SessionLocal()

    try:
        batch_id  = int(data["batch_id"])
        sensor_id = data.get("sensor_id", "").strip() or None
        temp      = float(data["temperature"])
        humidity  = float(data["humidity"])

        batch_check = db.execute(
            text("SELECT batch_id FROM batches WHERE batch_id = :id"),
            {"id": batch_id}
        ).fetchone()

        if not batch_check:
            return {"message": "Invalid batch ID"}

        is_violation = temp > 50

        db.execute(
            text("""
                INSERT INTO iot_readings (batch_id, sensor_id, temperature, humidity, is_violation)
                VALUES (:batch_id, :sensor_id, :temp, :humidity, :violation)
            """),
            {
                "batch_id":  batch_id,
                "sensor_id": sensor_id,
                "temp":      temp,
                "humidity":  humidity,
                "violation": is_violation
            }
        )

        log_event(db, batch_id, "IoT data recorded", category="IOT")

        if is_violation:
            log_event(db, batch_id, "Temperature violation detected", category="IOT")
            background_tasks.add_task(bg_recalculate_score_on_violation, batch_id)

        db.commit()

        if is_violation:
            return {"message": "⚠️ Violation detected! Score recalculation queued."}

        return {"message": "IoT data stored"}

    except Exception as e:
        db.rollback()
        return {"message": f"Error: {str(e)}"}

    finally:
        db.close()

# =========================
# CONSUMER VIEW
# =========================
@app.get("/product/{batch_id}")
def get_product(batch_id: int):
    db = SessionLocal()

    try:
        result = db.execute(
            text("""
                SELECT c.component_id, c.name, c.ethical_score, s.company_name, b.batch_uuid
                FROM batches b
                JOIN components c ON b.component_id = c.component_id
                JOIN suppliers s ON b.supplier_id = s.supplier_id
                WHERE b.batch_id = :id
            """),
            {"id": batch_id}
        ).fetchone()

        if not result:
            return {"message": "Batch not found"}

        component_id = result[0]
        total_score = calculate_recursive_score(db, component_id)

        violations = db.execute(
            text("""
                SELECT temperature, humidity, timestamp
                FROM iot_readings
                WHERE batch_id = :id AND is_violation = TRUE
            """),
            {"id": batch_id}
        ).fetchall()

        logs = db.execute(
            text("""
                SELECT event, timestamp
                FROM audit_logs
                WHERE batch_id = :id
                ORDER BY timestamp DESC
            """),
            {"id": batch_id}
        ).fetchall()

        status = "Violated" if len(violations) > 0 else "Safe"

        return {
            "batch_uuid": str(result[4]),
            "product": result[1],
            "origin": result[3],
            "ethical_score": total_score,
            "status": status,
            "violations": [
                {
                    "temperature": v[0],
                    "humidity": v[1],
                    "timestamp": str(v[2])
                } for v in violations
            ],
            "audit_logs": [
                {
                    "event": log[0],
                    "timestamp": str(log[1])
                } for log in logs
            ]
        }

    except Exception as e:
        db.rollback()
        return {"message": f"Error: {str(e)}"}

    finally:
        db.close()

# =========================
# ETHICAL METRICS
# =========================
@app.post("/metrics")
def submit_metric(data: dict, token_data: dict = Depends(verify_token)):
    """Supplier submits an ethical metric value for a component."""
    if token_data["role"] != "Supplier":
        raise HTTPException(status_code=403, detail="Only Suppliers can submit ethical metrics")

    db = SessionLocal()

    try:
        component_id = int(data["component_id"])
        metric_name  = data.get("metric_name", "").strip()
        metric_value = float(data["metric_value"])

        if not metric_name:
            return {"success": False, "error": "metric_name is required"}

        component = db.execute(
            text("SELECT component_id FROM components WHERE component_id = :id"),
            {"id": component_id}
        ).fetchone()

        if not component:
            return {"success": False, "error": "Component not found"}

        result = db.execute(
            text("""
                INSERT INTO ethical_metrics (component_id, metric_name, metric_value, recorded_by)
                VALUES (:component_id, :metric_name, :metric_value, :recorded_by)
                RETURNING metric_id
            """),
            {
                "component_id": component_id,
                "metric_name":  metric_name,
                "metric_value": metric_value,
                "recorded_by":  token_data["user_id"]
            }
        )
        metric_id = result.fetchone()[0]
        db.commit()

        return {"success": True, "metric_id": metric_id}

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()


@app.get("/metrics/{component_id}")
def get_metrics(component_id: int, token_data: dict = Depends(verify_token)):
    """Retrieve all ethical metrics recorded for a component."""
    db = SessionLocal()

    try:
        component = db.execute(
            text("SELECT component_id FROM components WHERE component_id = :id"),
            {"id": component_id}
        ).fetchone()

        if not component:
            return {"success": False, "error": "Component not found"}

        rows = db.execute(
            text("""
                SELECT metric_name, metric_value, recorded_by, recorded_at
                FROM ethical_metrics
                WHERE component_id = :id
                ORDER BY recorded_at DESC
            """),
            {"id": component_id}
        ).fetchall()

        return {
            "success": True,
            "component_id": component_id,
            "metrics": [
                {
                    "metric_name":  r[0],
                    "metric_value": r[1],
                    "recorded_by":  r[2],
                    "recorded_at":  str(r[3])
                } for r in rows
            ]
        }

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# REFRESH MATERIALIZED VIEW (Admin only)
# =========================
@app.post("/refresh-scores")
def refresh_scores(token_data: dict = Depends(verify_token)):
    if token_data["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Only Admins can refresh scores")

    db = SessionLocal()
    try:
        db.execute(text("REFRESH MATERIALIZED VIEW CONCURRENTLY component_scores_mv"))
        db.commit()
        return {"success": True, "message": "Materialized view refreshed"}
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()

# =========================
# QR CODE
# =========================
@app.get("/qr/{batch_uuid}")
def get_qr(batch_uuid: str):
    db = SessionLocal()

    try:
        result = db.execute(
            text("SELECT batch_id FROM batches WHERE batch_uuid = :uuid"),
            {"uuid": batch_uuid}
        ).fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Batch not found")

        batch_id = result[0]
        public_url = f"http://127.0.0.1:8000/product/{batch_id}"

        img = qrcode.make(public_url)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        return StreamingResponse(buf, media_type="image/png")

    except HTTPException:
        raise

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        db.close()

# =========================
# HEALTH CHECK
# =========================
@app.get("/health")
def health():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception:
        return {"status": "error", "db": "disconnected"}
    finally:
        db.close()

# =========================
# LOGIN
# =========================
@app.post("/login")
def login(data: dict):
    db = SessionLocal()

    try:
        result = db.execute(
            text("SELECT user_id, name, role, password, mfa_secret FROM users WHERE email = :email"),
            {"email": data["email"]}
        ).fetchone()

        if not result or not verify_password(data["password"], result[3]):
            return {"success": False, "error": "Invalid email or password"}

        user_id, name, role, _, mfa_secret = result

        # MFA required for Admin and Auditor if secret is configured
        # MFA required for Admin and Auditor — hard block if not configured
        if role in ("Admin", "Auditor"):
            if not mfa_secret:
                return {
                    "success": False,
                    "error": "MFA not configured. Call /setup-mfa to set it up first."
                }
            return {
                "success": True,
                "mfa_required": True,
                "user_id": user_id,
                "role": role
            }

        token = create_access_token({"user_id": user_id, "role": role})

        return {
            "success": True,
            "mfa_required": False,
            "user_id": user_id,
            "name": name,
            "role": role,
            "token": token
        }

    except Exception as e:
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# MFA VERIFICATION
# =========================
@app.post("/verify-mfa")
def verify_mfa(data: dict):
    """Second step for Admin/Auditor login when MFA is configured.
    Accepts user_id + TOTP code, returns JWT on success."""
    db = SessionLocal()

    try:
        user_id = int(data["user_id"])
        code    = str(data["code"]).strip()

        result = db.execute(
            text("SELECT role, mfa_secret FROM users WHERE user_id = :id"),
            {"id": user_id}
        ).fetchone()

        if not result:
            return {"success": False, "error": "User not found"}

        role, mfa_secret = result

        if not mfa_secret:
            return {"success": False, "error": "MFA not configured for this user"}

        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(code):
            return {"success": False, "error": "Invalid MFA code"}

        token = create_access_token({"user_id": user_id, "role": role})

        return {"success": True, "token": token}

    except Exception as e:
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# MFA SETUP
# =========================
@app.post("/setup-mfa")
def setup_mfa(token_data: dict = Depends(verify_token)):
    """Generates and stores a TOTP secret for the authenticated user.
    Only available to Admin and Auditor roles."""
    if token_data["role"] not in ("Admin", "Auditor"):
        raise HTTPException(status_code=403, detail="MFA setup is only available for Admin and Auditor roles")

    db = SessionLocal()

    try:
        secret = pyotp.random_base32()

        db.execute(
            text("UPDATE users SET mfa_secret = :secret WHERE user_id = :id"),
            {"secret": secret, "id": token_data["user_id"]}
        )
        db.commit()

        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=str(token_data["user_id"]),
            issuer_name="SupplyChain Analyzer"
        )

        return {
            "success": True,
            "mfa_secret": secret,
            "totp_uri": totp_uri,
            "message": "Scan the totp_uri with an authenticator app (e.g. Google Authenticator)"
        }

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# REGISTER
# =========================
@app.post("/register")
def register(data: dict):
    db = SessionLocal()

    try:
        name     = data.get("name", "").strip()
        email    = data.get("email", "").strip()
        password = data.get("password", "").strip()
        role     = data.get("role", "").strip()

        if not name or not email or not password or not role:
            return {"success": False, "error": "All fields are required"}

        if role not in ("Supplier", "Consumer"):
            return {"success": False, "error": "Role must be Supplier or Consumer"}

        hashed_password = hash_password(password)

        result = db.execute(
            text("""
                INSERT INTO users (name, email, password, role)
                VALUES (:name, :email, :password, :role)
                RETURNING user_id
            """),
            {"name": name, "email": email, "password": hashed_password, "role": role}
        )
        user_id = result.fetchone()[0]

        if role == "Supplier":
            db.execute(
                text("""
                    INSERT INTO suppliers (supplier_id, company_name, compliance_status)
                    VALUES (:user_id, :company_name, 'Compliant')
                """),
                {"user_id": user_id, "company_name": name}
            )

        db.commit()

        return {"success": True, "user_id": user_id, "name": name, "role": role}

    except Exception as e:
        db.rollback()
        error_msg = str(e)
        if "duplicate key" in error_msg or "unique" in error_msg.lower():
            return {"success": False, "error": "An account with this email already exists"}
        return {"success": False, "error": error_msg}

    finally:
        db.close()

# =========================
# AUDIT LOGS (queryable)
# =========================
@app.get("/audit-logs")
def get_audit_logs(
    batch_id: int = None,
    event_category: str = None,
    limit: int = 100,
    token_data: dict = Depends(verify_token)
):
    if token_data["role"] not in ("Admin", "Auditor"):
        raise HTTPException(status_code=403, detail="Only Admin and Auditor can access audit logs")

    db = SessionLocal()

    try:
        filters = []
        params  = {"limit": limit}

        if batch_id is not None:
            filters.append("batch_id = :batch_id")
            params["batch_id"] = batch_id

        if event_category is not None:
            filters.append("event_category = :category")
            params["category"] = event_category

        where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

        rows = db.execute(
            text(f"""
                SELECT log_id, batch_id, event, event_category, triggered_by, timestamp
                FROM audit_logs
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT :limit
            """),
            params
        ).fetchall()

        return {
            "success": True,
            "count": len(rows),
            "logs": [
                {
                    "log_id":         r[0],
                    "batch_id":       r[1],
                    "event":          r[2],
                    "event_category": r[3],
                    "triggered_by":   r[4],
                    "timestamp":      str(r[5])
                } for r in rows
            ]
        }

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# SUPPLIER STATUS
# =========================
@app.get("/supplier/{supplier_id}/status")
def supplier_status(supplier_id: int, token_data: dict = Depends(verify_token)):
    if token_data["role"] not in ("Auditor", "Admin"):
        raise HTTPException(status_code=403, detail="Only Auditors can view supplier status")

    db = SessionLocal()

    try:
        result = db.execute(
            text("SELECT company_name, compliance_status FROM suppliers WHERE supplier_id = :id"),
            {"id": supplier_id}
        ).fetchone()

        if not result:
            return {"success": False, "error": "Supplier not found"}

        return {
            "success": True,
            "company_name": result[0],
            "compliance_status": result[1]
        }

    except Exception as e:
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# ISSUE CERTIFICATE (Auditor)
# =========================
@app.post("/issue-certificate")
def issue_certificate(data: dict, token_data: dict = Depends(verify_token)):
    db = SessionLocal()

    try:
        batch_id   = int(data["batch_id"])
        auditor_id = int(data["auditor_id"])
        notes      = data.get("notes", "").strip()

        auditor = db.execute(
            text("SELECT role FROM users WHERE user_id = :id"),
            {"id": auditor_id}
        ).fetchone()

        if not auditor or auditor[0] != "Auditor":
            return {"success": False, "error": "Only Auditors can issue certificates"}

        batch_check = db.execute(
            text("SELECT batch_id FROM batches WHERE batch_id = :id"),
            {"id": batch_id}
        ).fetchone()

        if not batch_check:
            return {"success": False, "error": "Invalid batch ID"}

        result = db.execute(
            text("""
                INSERT INTO ethical_certificates (batch_id, issued_by, notes)
                VALUES (:batch_id, :issued_by, :notes)
                RETURNING certificate_id
            """),
            {"batch_id": batch_id, "issued_by": auditor_id, "notes": notes}
        )
        certificate_id = result.fetchone()[0]

        log_event(db, batch_id, f"Ethical certificate {certificate_id} issued by auditor {auditor_id}",
                  category="CERTIFICATE", triggered_by=auditor_id)

        db.commit()

        return {"success": True, "certificate_id": certificate_id}

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()

# =========================
# APPROVE SUPPLIER (Admin)
# =========================
@app.post("/approve-supplier")
def approve_supplier(data: dict, background_tasks: BackgroundTasks, token_data: dict = Depends(verify_token)):
    db = SessionLocal()

    try:
        supplier_id       = int(data["supplier_id"])
        admin_id          = int(data["admin_id"])
        compliance_status = data.get("compliance_status", "").strip()

        admin = db.execute(
            text("SELECT role FROM users WHERE user_id = :id"),
            {"id": admin_id}
        ).fetchone()

        if not admin or admin[0] != "Admin":
            return {"success": False, "error": "Only Admins can update supplier compliance"}

        if compliance_status not in ("Compliant", "Violated"):
            return {"success": False, "error": "Status must be Compliant or Violated"}

        supplier = db.execute(
            text("SELECT company_name FROM suppliers WHERE supplier_id = :id"),
            {"id": supplier_id}
        ).fetchone()

        if not supplier:
            return {"success": False, "error": "Supplier not found"}

        db.execute(
            text("UPDATE suppliers SET compliance_status = :status WHERE supplier_id = :id"),
            {"status": compliance_status, "id": supplier_id}
        )

        db.commit()

        background_tasks.add_task(
            bg_recalculate_scores_for_supplier,
            supplier_id,
            compliance_status,
            admin_id
        )

        return {
            "success": True,
            "supplier_id": supplier_id,
            "company_name": supplier[0],
            "new_status": compliance_status,
            "message": "Score recalculation queued."
        }

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()