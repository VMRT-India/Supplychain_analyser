-- =========================
-- DATABASE: supplychain_analyzer
-- =========================

-- USERS TABLE
CREATE TABLE users (
    user_id    SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    role       TEXT CHECK (role IN ('Admin', 'Auditor', 'Supplier', 'Consumer')) NOT NULL,
    mfa_secret TEXT DEFAULT NULL  -- NULL means MFA not configured
);

-- SUPPLIER TABLE (extends users)
CREATE TABLE suppliers (
    supplier_id INT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    company_name TEXT,
    compliance_status TEXT DEFAULT 'Compliant' CHECK (compliance_status IN ('Compliant', 'Violated'))
);

-- COMPONENT TABLE (recursive tree)
CREATE TABLE components (
    component_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id INT REFERENCES components(component_id) ON DELETE CASCADE,
    ethical_score FLOAT DEFAULT 10
);

-- BATCH TABLE
CREATE TABLE batches (
    batch_id SERIAL PRIMARY KEY,
    batch_uuid UUID DEFAULT gen_random_uuid() NOT NULL UNIQUE,
    component_id INT REFERENCES components(component_id),
    supplier_id INT REFERENCES suppliers(supplier_id),
    quantity INT,
    status TEXT DEFAULT 'Active'
);

-- AUDIT LOG (immutable, append-only)
CREATE TABLE audit_logs (
    log_id         SERIAL PRIMARY KEY,
    batch_id       INT REFERENCES batches(batch_id),
    event          TEXT,
    event_category TEXT CHECK (event_category IN ('BATCH', 'IOT', 'COMPLIANCE', 'CERTIFICATE', 'AUTH', 'SYSTEM')) DEFAULT 'SYSTEM',
    triggered_by   INT REFERENCES users(user_id) DEFAULT NULL,
    timestamp      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IOT READINGS
CREATE TABLE iot_readings (
    reading_id SERIAL PRIMARY KEY,
    batch_id INT REFERENCES batches(batch_id),
    sensor_id TEXT,
    temperature FLOAT,
    humidity FLOAT,
    is_violation BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


INSERT INTO users (name, email, password, role) VALUES
('Admin One', 'admin@test.com', '$2b$12$9hn1vhUChnHDjERFNpdoWuxo8c/FtCncME/N1EhE7ntd5v3DGu1xG', 'Admin'),
('Auditor One', 'auditor@test.com', '$2b$12$9hn1vhUChnHDjERFNpdoWuxo8c/FtCncME/N1EhE7ntd5v3DGu1xG', 'Auditor'),
('Supplier One', 'supplier1@test.com', '$2b$12$9hn1vhUChnHDjERFNpdoWuxo8c/FtCncME/N1EhE7ntd5v3DGu1xG', 'Supplier'),
('Supplier Two', 'supplier2@test.com', '$2b$12$9hn1vhUChnHDjERFNpdoWuxo8c/FtCncME/N1EhE7ntd5v3DGu1xG', 'Supplier'),
('Supplier Three', 'supplier3@test.com', '$2b$12$9hn1vhUChnHDjERFNpdoWuxo8c/FtCncME/N1EhE7ntd5v3DGu1xG', 'Supplier'),
('Consumer One', 'consumer@test.com', '$2b$12$9hn1vhUChnHDjERFNpdoWuxo8c/FtCncME/N1EhE7ntd5v3DGu1xG', 'Consumer');
-- Note: all seed passwords above are bcrypt hash of '123'

INSERT INTO suppliers (supplier_id, company_name, compliance_status) VALUES
(3, 'Steel Corp', 'Compliant'),
(4, 'Mining Ltd', 'Violated'),
(5, 'Textile Works', 'Compliant');

INSERT INTO components (name, parent_id, ethical_score) VALUES
-- Raw materials
('Iron Ore', NULL, 10),
('Coal', NULL, 8),
('Cotton', NULL, 9),

-- Level 1 processing
('Steel', 1, 20),
('Fabric', 3, 18),

-- Final products
('Car Body', 4, 30),
('T-Shirt', 5, 25);

INSERT INTO batches (component_id, supplier_id, quantity, status) VALUES
(4, 3, 100, 'Active'),   -- Steel batch
(5, 5, 200, 'Active'),   -- Fabric batch
(6, 3, 50, 'Active'),    -- Car Body
(7, 5, 150, 'Active');   -- T-Shirt

INSERT INTO audit_logs (batch_id, event, event_category) VALUES
(1, 'Batch Created',          'BATCH'),
(1, 'Quality Check Passed',   'BATCH'),
(2, 'Batch Created',          'BATCH'),
(2, 'Minor Delay Reported',   'BATCH'),
(3, 'Batch Created',          'BATCH'),
(4, 'Batch Created',          'BATCH');

INSERT INTO iot_readings (batch_id, sensor_id, temperature, humidity, is_violation) VALUES
(1, 'SENSOR-A1', 25, 60, FALSE),
(1, 'SENSOR-A1', 55, 70, TRUE),   -- violation
(2, 'SENSOR-B1', 22, 50, FALSE),
(3, 'SENSOR-C1', 30, 65, FALSE),
(4, 'SENSOR-D1', 60, 80, TRUE);   -- violation

-- =========================
-- ETHICAL METRICS (extensible key-value store per component)
-- Supports carbon_footprint, worker_safety_score, and future metrics
-- without redesigning existing data relationships.
-- =========================
CREATE TABLE ethical_metrics (
    metric_id    SERIAL PRIMARY KEY,
    component_id INT REFERENCES components(component_id) ON DELETE CASCADE,
    metric_name  TEXT NOT NULL,
    metric_value FLOAT NOT NULL,
    recorded_by  INT REFERENCES users(user_id),
    recorded_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- MATERIALIZED VIEW: PRE-COMPUTED RECURSIVE ETHICAL SCORES
-- Stores the total recursive ethical score per component.
-- Query /score/{id} reads from here instead of running the CTE each time.
-- Refresh via POST /refresh-scores (Admin only) when underlying data changes.
-- =========================
CREATE MATERIALIZED VIEW component_scores_mv AS
WITH RECURSIVE component_tree AS (
    SELECT component_id AS root_id, component_id, ethical_score
    FROM components

    UNION ALL

    SELECT ct.root_id, c.component_id, c.ethical_score
    FROM components c
    INNER JOIN component_tree ct ON c.parent_id = ct.component_id
)
SELECT root_id AS component_id, SUM(ethical_score) AS total_score
FROM component_tree
GROUP BY root_id;

CREATE UNIQUE INDEX ON component_scores_mv (component_id);

-- =========================
-- COMPLIANCE TRIGGER
-- Blocks batch insertion if supplier compliance_status is 'Violated'.
-- Enforced at DB level independent of application logic.
-- =========================
CREATE OR REPLACE FUNCTION check_supplier_compliance()
RETURNS TRIGGER AS $$
DECLARE
    supplier_status TEXT;
BEGIN
    SELECT compliance_status INTO supplier_status
    FROM suppliers
    WHERE supplier_id = NEW.supplier_id;

    IF supplier_status = 'Violated' THEN
        RAISE EXCEPTION 'Batch creation blocked: supplier % has compliance status Violated', NEW.supplier_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_supplier_compliance
BEFORE INSERT ON batches
FOR EACH ROW
EXECUTE FUNCTION check_supplier_compliance();

-- =========================
-- AUDIT LOG IMMUTABILITY
-- Prevents DELETE and UPDATE on audit_logs to enforce append-only semantics.
-- =========================
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be deleted or modified';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_modification();

CREATE TRIGGER trg_audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_modification();

-- ETHICAL CERTIFICATES
CREATE TABLE ethical_certificates (
    certificate_id SERIAL PRIMARY KEY,
    batch_id       INT REFERENCES batches(batch_id),
    issued_by      INT REFERENCES users(user_id),
    notes          TEXT,
    issued_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);