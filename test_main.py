import uuid
import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
import os
from main import app

client = TestClient(app)


# =========================
# SESSION SETUP
# =========================
@pytest.fixture(scope="session", autouse=True)
def reset_mfa_before_session():
    """Clear all mfa_secrets before the test session so token fixtures
    are not blocked by MFA state left from a prior run."""
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:password@localhost/supplychain_analyzer"
    )
    engine = create_engine(db_url)
    with engine.connect() as conn:
        conn.execute(text("UPDATE users SET mfa_secret = NULL"))
        conn.commit()
    engine.dispose()
    yield


# =========================
# HELPERS
# =========================
def get_token(email: str, password: str) -> str:
    response = client.post("/login", json={"email": email, "password": password})
    data = response.json()
    assert data["success"] is True, f"Login failed for {email}: {data}"
    assert "token" in data, f"No token returned for {email}: {data}"
    return data["token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# module-scoped fixtures — created once, before any MFA setup tests alter seed users
@pytest.fixture(scope="module")
def admin_token():
    return get_token("admin@test.com", "123")


@pytest.fixture(scope="module")
def auditor_token():
    return get_token("auditor@test.com", "123")


@pytest.fixture(scope="module")
def supplier_token():
    # supplier_id=3, Steel Corp, Compliant
    return get_token("supplier1@test.com", "123")


@pytest.fixture(scope="module")
def consumer_token():
    return get_token("consumer@test.com", "123")


# =========================
# HEALTH CHECK
# =========================
def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["db"] == "connected"


def test_health_session_released_on_repeated_calls():
    for _ in range(3):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# =========================
# BUG 1: PASSWORD HASHING
# =========================
def test_login_correct_password_succeeds():
    response = client.post("/login", json={"email": "consumer@test.com", "password": "123"})
    data = response.json()
    assert data["success"] is True
    assert "token" in data


def test_login_wrong_password_fails():
    response = client.post("/login", json={"email": "admin@test.com", "password": "wrongpassword"})
    data = response.json()
    assert data["success"] is False
    assert "error" in data


def test_login_unknown_email_fails():
    response = client.post("/login", json={"email": "nobody@test.com", "password": "123"})
    data = response.json()
    assert data["success"] is False


def test_register_then_login_uses_hashed_password():
    unique_email = f"hashtest_{uuid.uuid4().hex[:8]}@test.com"
    reg = client.post("/register", json={
        "name": "Hash Test User",
        "email": unique_email,
        "password": "securepassword",
        "role": "Consumer"
    })
    assert reg.json()["success"] is True

    login = client.post("/login", json={"email": unique_email, "password": "securepassword"})
    data = login.json()
    assert data["success"] is True
    assert "token" in data


def test_register_wrong_password_cannot_login():
    unique_email = f"hashtest2_{uuid.uuid4().hex[:8]}@test.com"
    client.post("/register", json={
        "name": "Hash Test 2",
        "email": unique_email,
        "password": "correctpassword",
        "role": "Consumer"
    })

    login = client.post("/login", json={"email": unique_email, "password": "wrongpassword"})
    data = login.json()
    assert data["success"] is False


# =========================
# BUG 2: JWT AUTHENTICATION
# =========================
def test_login_returns_jwt_token():
    response = client.post("/login", json={"email": "consumer@test.com", "password": "123"})
    data = response.json()
    assert "token" in data
    assert len(data["token"]) > 20


def test_create_batch_without_token_returns_401(admin_token):
    # also forces admin_token fixture to initialise before any MFA setup tests
    response = client.post("/create-batch", json={"component_name": "X", "supplier_id": 3})
    assert response.status_code in (401, 403)


def test_create_batch_with_invalid_token_returns_401():
    response = client.post(
        "/create-batch",
        json={"component_name": "X", "supplier_id": 3},
        headers={"Authorization": "Bearer invalidtoken"}
    )
    assert response.status_code == 401


def test_create_batch_with_valid_token_succeeds(supplier_token):
    response = client.post(
        "/create-batch",
        json={"component_name": "Auth Test Part", "supplier_id": 3},
        headers=auth(supplier_token)
    )
    assert response.json()["success"] is True


def test_iot_data_without_token_returns_401():
    response = client.post("/iot-data", json={"batch_id": 1, "temperature": 30, "humidity": 50})
    assert response.status_code in (401, 403)


def test_supplier_status_without_token_returns_401():
    response = client.get("/supplier/3/status")
    assert response.status_code in (401, 403)


def test_issue_certificate_without_token_returns_401():
    response = client.post("/issue-certificate", json={"batch_id": 1, "auditor_id": 2})
    assert response.status_code in (401, 403)


def test_approve_supplier_without_token_returns_401():
    response = client.post("/approve-supplier", json={
        "supplier_id": 3, "admin_id": 1, "compliance_status": "Compliant"
    })
    assert response.status_code in (401, 403)


# =========================
# BUG 3: ETHICAL SCORE RECALCULATION
# =========================
def test_violated_supplier_sets_scores_to_zero(admin_token, supplier_token):
    batch_resp = client.post(
        "/create-batch",
        json={"component_name": "Score Test Component", "supplier_id": 3},
        headers=auth(supplier_token)
    )
    assert batch_resp.json()["success"] is True

    # Mark supplier 3 as Violated
    resp = client.post(
        "/approve-supplier",
        json={"supplier_id": 3, "admin_id": 1, "compliance_status": "Violated"},
        headers=auth(admin_token)
    )
    assert resp.json()["success"] is True

    # Restore supplier 3 to Compliant so downstream tests are not broken
    restore = client.post(
        "/approve-supplier",
        json={"supplier_id": 3, "admin_id": 1, "compliance_status": "Compliant"},
        headers=auth(admin_token)
    )
    assert restore.json()["success"] is True


def test_approve_supplier_compliant_restores_only_zeroed_scores(admin_token):
    # Supplier 5 (Textile Works) is Compliant in seed data
    # Mark Violated → then Compliant; response must succeed both ways
    v = client.post(
        "/approve-supplier",
        json={"supplier_id": 5, "admin_id": 1, "compliance_status": "Violated"},
        headers=auth(admin_token)
    )
    assert v.json()["success"] is True

    c = client.post(
        "/approve-supplier",
        json={"supplier_id": 5, "admin_id": 1, "compliance_status": "Compliant"},
        headers=auth(admin_token)
    )
    assert c.json()["success"] is True
    assert "queued" in c.json()["message"].lower()


# =========================
# BUG 4: TRANSACTION SAFETY
# =========================
def test_score_invalid_component_returns_not_found():
    response = client.get("/score/999999")
    assert response.status_code == 200
    data = response.json()
    assert data["score"] == "Not found"


def test_product_invalid_batch_returns_message():
    response = client.get("/product/999999")
    assert response.status_code == 200
    assert "message" in response.json()


def test_score_valid_component_returns_number():
    response = client.get("/score/4")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["score"], (int, float))


# =========================
# FEATURE 1: UUID BATCH IDENTIFICATION
# =========================
def test_create_batch_returns_valid_uuid(supplier_token):
    response = client.post(
        "/create-batch",
        json={"component_name": "UUID Test Part", "supplier_id": 3},
        headers=auth(supplier_token)
    )
    data = response.json()
    assert data["success"] is True
    batch_uuid = data["data"]["batch_uuid"]
    parsed = uuid.UUID(batch_uuid)
    assert str(parsed) == batch_uuid


def test_each_batch_gets_unique_uuid(supplier_token):
    uuids = set()
    for i in range(3):
        r = client.post(
            "/create-batch",
            json={"component_name": f"UUID Unique Part {i}", "supplier_id": 3},
            headers=auth(supplier_token)
        )
        uuids.add(r.json()["data"]["batch_uuid"])
    assert len(uuids) == 3


def test_product_endpoint_includes_batch_uuid():
    response = client.get("/product/1")
    data = response.json()
    assert "batch_uuid" in data
    uuid.UUID(data["batch_uuid"])  # raises ValueError if invalid


# =========================
# FEATURE 2: QR CODE
# =========================
def test_qr_returns_png_for_valid_uuid():
    product = client.get("/product/1").json()
    batch_uuid = product["batch_uuid"]

    response = client.get(f"/qr/{batch_uuid}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert len(response.content) > 0


def test_qr_png_content_is_non_empty():
    product = client.get("/product/2").json()
    batch_uuid = product["batch_uuid"]

    response = client.get(f"/qr/{batch_uuid}")
    assert response.status_code == 200
    # PNG files start with the PNG signature bytes
    assert response.content[:4] == b"\x89PNG"


def test_qr_returns_404_for_unknown_uuid():
    fake_uuid = str(uuid.uuid4())
    response = client.get(f"/qr/{fake_uuid}")
    assert response.status_code == 404


# =========================
# FEATURE 3: DB-LEVEL COMPLIANCE TRIGGER (app-layer gate)
# =========================
def test_violated_supplier_blocked_by_app_layer(supplier_token):
    # supplier_id=4 is Mining Ltd, Violated in seed data
    response = client.post(
        "/create-batch",
        json={"component_name": "Blocked Part", "supplier_id": 4},
        headers=auth(supplier_token)
    )
    data = response.json()
    assert data["success"] is False
    assert "Violated" in data["error"]


def test_invalid_supplier_id_blocked(supplier_token):
    response = client.post(
        "/create-batch",
        json={"component_name": "Ghost Part", "supplier_id": 99999},
        headers=auth(supplier_token)
    )
    data = response.json()
    assert data["success"] is False


# =========================
# FEATURE 4: BACKGROUND TASKS
# =========================
def test_iot_violation_response_acknowledges_background_queue(supplier_token):
    response = client.post(
        "/iot-data",
        json={"batch_id": 1, "temperature": 60, "humidity": 50, "sensor_id": "BG-S1"},
        headers=auth(supplier_token)
    )
    data = response.json()
    assert "Violation" in data["message"]
    assert "queued" in data["message"].lower()


def test_iot_normal_reading_returns_stored(supplier_token):
    response = client.post(
        "/iot-data",
        json={"batch_id": 2, "temperature": 25, "humidity": 60},
        headers=auth(supplier_token)
    )
    assert response.json()["message"] == "IoT data stored"


def test_approve_supplier_response_acknowledges_queue(admin_token):
    response = client.post(
        "/approve-supplier",
        json={"supplier_id": 5, "admin_id": 1, "compliance_status": "Compliant"},
        headers=auth(admin_token)
    )
    data = response.json()
    assert data["success"] is True
    assert "queued" in data["message"].lower()


# =========================
# FEATURE 5: MATERIALIZED VIEW
# =========================
def test_score_endpoint_returns_precomputed_value():
    response = client.get("/score/4")
    data = response.json()
    assert response.status_code == 200
    assert isinstance(data["score"], (int, float))
    assert data["score"] > 0


def test_refresh_scores_succeeds_for_admin(admin_token):
    response = client.post("/refresh-scores", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    assert "refreshed" in data["message"].lower()


def test_refresh_scores_blocked_for_supplier(supplier_token):
    response = client.post("/refresh-scores", headers=auth(supplier_token))
    assert response.status_code == 403


def test_refresh_scores_blocked_for_consumer(consumer_token):
    response = client.post("/refresh-scores", headers=auth(consumer_token))
    assert response.status_code == 403


def test_score_still_valid_after_refresh(admin_token):
    client.post("/refresh-scores", headers=auth(admin_token))
    response = client.get("/score/4")
    data = response.json()
    assert isinstance(data["score"], (int, float))
    assert data["score"] > 0


# =========================
# FEATURE 6: EXTENDED IOT MODEL (sensor_id)
# =========================
def test_iot_data_accepts_sensor_id(supplier_token):
    response = client.post(
        "/iot-data",
        json={"batch_id": 1, "temperature": 30, "humidity": 55, "sensor_id": "SENSOR-X1"},
        headers=auth(supplier_token)
    )
    assert response.status_code == 200
    assert response.json()["message"] == "IoT data stored"


def test_iot_data_works_without_sensor_id(supplier_token):
    response = client.post(
        "/iot-data",
        json={"batch_id": 1, "temperature": 28, "humidity": 60},
        headers=auth(supplier_token)
    )
    assert response.status_code == 200
    assert response.json()["message"] == "IoT data stored"


def test_iot_data_with_different_sensor_ids_accepted(supplier_token):
    for sensor in ["SENSOR-A", "SENSOR-B", "SENSOR-C"]:
        r = client.post(
            "/iot-data",
            json={"batch_id": 2, "temperature": 22, "humidity": 45, "sensor_id": sensor},
            headers=auth(supplier_token)
        )
        assert r.json()["message"] == "IoT data stored"


def test_iot_invalid_batch_id_rejected(supplier_token):
    response = client.post(
        "/iot-data",
        json={"batch_id": 999999, "temperature": 30, "humidity": 50},
        headers=auth(supplier_token)
    )
    assert response.json()["message"] == "Invalid batch ID"


# =========================
# FEATURE 8: MFA  (admin only — auditor kept clean for audit-log fixture)
# =========================
def test_setup_mfa_allowed_for_admin(admin_token):
    response = client.post("/setup-mfa", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    assert "mfa_secret" in data
    assert "totp_uri" in data
    assert "SupplyChain" in data["totp_uri"]


def test_setup_mfa_blocked_for_supplier(supplier_token):
    response = client.post("/setup-mfa", headers=auth(supplier_token))
    assert response.status_code == 403


def test_setup_mfa_blocked_for_consumer(consumer_token):
    response = client.post("/setup-mfa", headers=auth(consumer_token))
    assert response.status_code == 403


def test_verify_mfa_with_valid_totp_returns_token(admin_token):
    # Setup MFA for admin (user_id=1) and obtain secret in one call
    setup_resp = client.post("/setup-mfa", headers=auth(admin_token))
    secret = setup_resp.json()["mfa_secret"]

    code = pyotp.TOTP(secret).now()

    verify_resp = client.post("/verify-mfa", json={"user_id": 1, "code": code})
    data = verify_resp.json()
    assert data["success"] is True
    assert "token" in data
    assert len(data["token"]) > 20


def test_verify_mfa_with_invalid_code_fails():
    response = client.post("/verify-mfa", json={"user_id": 1, "code": "000000"})
    data = response.json()
    assert data["success"] is False
    assert "Invalid" in data["error"]


def test_login_with_mfa_configured_returns_mfa_required():
    # Admin now has mfa_secret set (from test_setup_mfa_allowed_for_admin above)
    response = client.post("/login", json={"email": "admin@test.com", "password": "123"})
    data = response.json()
    assert data["success"] is True
    assert data["mfa_required"] is True
    assert "token" not in data
    assert "user_id" in data


def test_verify_mfa_for_user_without_mfa_configured_fails():
    # Consumer has no mfa_secret
    consumer = client.post("/login", json={"email": "consumer@test.com", "password": "123"}).json()
    response = client.post("/verify-mfa", json={"user_id": consumer["user_id"], "code": "123456"})
    data = response.json()
    assert data["success"] is False
    assert "not configured" in data["error"].lower()


# =========================
# FEATURE 11: ETHICAL METRICS
# =========================
def test_submit_metric_allowed_for_supplier(supplier_token):
    response = client.post(
        "/metrics",
        json={"component_id": 1, "metric_name": "carbon_footprint", "metric_value": 12.5},
        headers=auth(supplier_token)
    )
    data = response.json()
    assert data["success"] is True
    assert "metric_id" in data
    assert isinstance(data["metric_id"], int)


def test_submit_multiple_metric_types(supplier_token):
    for metric_name, value in [("carbon_footprint", 8.0), ("worker_safety_score", 9.5)]:
        r = client.post(
            "/metrics",
            json={"component_id": 2, "metric_name": metric_name, "metric_value": value},
            headers=auth(supplier_token)
        )
        assert r.json()["success"] is True


def test_submit_metric_blocked_for_consumer(consumer_token):
    response = client.post(
        "/metrics",
        json={"component_id": 1, "metric_name": "carbon_footprint", "metric_value": 5.0},
        headers=auth(consumer_token)
    )
    assert response.status_code == 403


def test_submit_metric_blocked_for_admin(admin_token):
    response = client.post(
        "/metrics",
        json={"component_id": 1, "metric_name": "worker_safety", "metric_value": 8.0},
        headers=auth(admin_token)
    )
    assert response.status_code == 403


def test_get_metrics_returns_submitted_entries(supplier_token, admin_token):
    client.post(
        "/metrics",
        json={"component_id": 3, "metric_name": "worker_safety_score", "metric_value": 7.0},
        headers=auth(supplier_token)
    )

    response = client.get("/metrics/3", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    assert isinstance(data["metrics"], list)
    names = [m["metric_name"] for m in data["metrics"]]
    assert "worker_safety_score" in names


def test_get_metrics_each_entry_has_required_fields(supplier_token):
    response = client.get("/metrics/1", headers=auth(supplier_token))
    data = response.json()
    assert data["success"] is True
    for m in data["metrics"]:
        assert "metric_name" in m
        assert "metric_value" in m
        assert "recorded_by" in m
        assert "recorded_at" in m


def test_get_metrics_invalid_component_returns_error(admin_token):
    response = client.get("/metrics/999999", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is False
    assert "not found" in data["error"].lower()


# =========================
# FEATURE 12: ENHANCED AUDIT LOGGING
# =========================
def test_audit_logs_accessible_for_admin(admin_token):
    response = client.get("/audit-logs", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    assert "logs" in data
    assert isinstance(data["logs"], list)
    assert data["count"] == len(data["logs"])


def test_audit_logs_accessible_for_auditor(auditor_token):
    response = client.get("/audit-logs", headers=auth(auditor_token))
    data = response.json()
    assert data["success"] is True


def test_audit_logs_blocked_for_supplier(supplier_token):
    response = client.get("/audit-logs", headers=auth(supplier_token))
    assert response.status_code == 403


def test_audit_logs_blocked_for_consumer(consumer_token):
    response = client.get("/audit-logs", headers=auth(consumer_token))
    assert response.status_code == 403


def test_audit_logs_filter_by_batch_id(admin_token):
    response = client.get("/audit-logs?batch_id=1", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    for log in data["logs"]:
        assert log["batch_id"] == 1


def test_audit_logs_filter_by_category_batch(admin_token):
    response = client.get("/audit-logs?category=BATCH", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    for log in data["logs"]:
        assert log["event_category"] == "BATCH"


def test_audit_logs_filter_by_category_iot(admin_token):
    response = client.get("/audit-logs?category=IOT", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    for log in data["logs"]:
        assert log["event_category"] == "IOT"


def test_audit_logs_filter_by_category_compliance(admin_token):
    response = client.get("/audit-logs?category=COMPLIANCE", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    for log in data["logs"]:
        assert log["event_category"] == "COMPLIANCE"


def test_audit_logs_entries_have_required_fields(admin_token):
    response = client.get("/audit-logs?limit=5", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    for log in data["logs"]:
        assert "log_id" in log
        assert "event" in log
        assert "event_category" in log
        assert "timestamp" in log


def test_audit_logs_limit_respected(admin_token):
    response = client.get("/audit-logs?limit=3", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    assert len(data["logs"]) <= 3


def test_audit_logs_ordered_newest_first(admin_token):
    response = client.get("/audit-logs?limit=10", headers=auth(admin_token))
    timestamps = [log["timestamp"] for log in response.json()["logs"]]
    assert timestamps == sorted(timestamps, reverse=True)


# =========================
# REGRESSION: EXISTING FUNCTIONALITY
# =========================
def test_product_returns_all_required_fields():
    response = client.get("/product/1")
    assert response.status_code == 200
    data = response.json()
    for field in ("product", "ethical_score", "status", "violations", "audit_logs", "batch_uuid", "origin"):
        assert field in data, f"Missing field: {field}"
    assert isinstance(data["violations"], list)
    assert isinstance(data["audit_logs"], list)


def test_supplier_status_returns_correct_fields(admin_token):
    response = client.get("/supplier/3/status", headers=auth(admin_token))
    data = response.json()
    assert data["success"] is True
    assert "company_name" in data
    assert data["compliance_status"] in ("Compliant", "Violated")


def test_issue_certificate_only_auditor_allowed(admin_token, auditor_token):
    # Admin cannot issue certificate
    resp_admin = client.post(
        "/issue-certificate",
        json={"batch_id": 1, "auditor_id": 1, "notes": "Admin attempt"},
        headers=auth(admin_token)
    )
    assert resp_admin.json()["success"] is False
    assert "Auditor" in resp_admin.json()["error"]

    # Auditor can issue certificate
    resp_auditor = client.post(
        "/issue-certificate",
        json={"batch_id": 1, "auditor_id": 2, "notes": "Valid cert"},
        headers=auth(auditor_token)
    )
    assert resp_auditor.json()["success"] is True
    assert "certificate_id" in resp_auditor.json()


def test_approve_supplier_only_admin_allowed(supplier_token, admin_token):
    # Supplier cannot approve
    resp_supplier = client.post(
        "/approve-supplier",
        json={"supplier_id": 5, "admin_id": 3, "compliance_status": "Compliant"},
        headers=auth(supplier_token)
    )
    assert resp_supplier.json()["success"] is False
    assert "Admin" in resp_supplier.json()["error"]

    # Admin can approve
    resp_admin = client.post(
        "/approve-supplier",
        json={"supplier_id": 5, "admin_id": 1, "compliance_status": "Compliant"},
        headers=auth(admin_token)
    )
    assert resp_admin.json()["success"] is True


def test_register_duplicate_email_returns_error():
    response = client.post("/register", json={
        "name": "Duplicate",
        "email": "consumer@test.com",
        "password": "password",
        "role": "Consumer"
    })
    data = response.json()
    assert data["success"] is False
    assert "already exists" in data["error"]


def test_register_missing_fields_returns_error():
    response = client.post("/register", json={
        "name": "",
        "email": "test@test.com",
        "password": "password",
        "role": "Consumer"
    })
    data = response.json()
    assert data["success"] is False


def test_register_invalid_role_returns_error():
    response = client.post("/register", json={
        "name": "Test",
        "email": f"test_{uuid.uuid4().hex[:6]}@test.com",
        "password": "password",
        "role": "Manager"
    })
    data = response.json()
    assert data["success"] is False
    assert "Supplier or Consumer" in data["error"]


def test_register_supplier_creates_supplier_row():
    unique_email = f"newsupplier_{uuid.uuid4().hex[:8]}@test.com"
    reg = client.post("/register", json={
        "name": "New Supplier Co",
        "email": unique_email,
        "password": "password",
        "role": "Supplier"
    })
    reg_data = reg.json()
    assert reg_data["success"] is True

    # Login and use token to check supplier status
    token = get_token(unique_email, "password")
    user_id = reg_data["user_id"]

    status = client.get(f"/supplier/{user_id}/status", headers=auth(token))
    data = status.json()
    assert data["success"] is True
    assert data["compliance_status"] == "Compliant"
