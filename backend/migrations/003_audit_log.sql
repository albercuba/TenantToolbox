CREATE TABLE audit_log (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  actor_id VARCHAR(36) REFERENCES staff_user(id),
  client_tenant_id VARCHAR(36) REFERENCES client_tenant(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,
  target_type VARCHAR(100),
  target_id VARCHAR(100),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_audit_log_organization_created ON audit_log(organization_id, created_at DESC);
CREATE INDEX ix_audit_log_tenant_created ON audit_log(client_tenant_id, created_at DESC);
