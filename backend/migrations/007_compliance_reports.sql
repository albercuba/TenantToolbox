CREATE TABLE compliance_control (
  id VARCHAR(36) PRIMARY KEY,
  framework VARCHAR(50) NOT NULL,
  control_id VARCHAR(100) NOT NULL,
  title VARCHAR(200) NOT NULL,
  baseline_control VARCHAR(100) NOT NULL,
  UNIQUE(framework, control_id)
);
CREATE TABLE report (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  report_type VARCHAR(50) NOT NULL,
  title VARCHAR(200) NOT NULL,
  content TEXT NOT NULL,
  created_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_report_tenant_created ON report(client_tenant_id, created_at DESC);
