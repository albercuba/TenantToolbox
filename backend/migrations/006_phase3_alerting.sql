ALTER TABLE alert ADD COLUMN source VARCHAR(50) NOT NULL DEFAULT 'drift';
ALTER TABLE alert ADD COLUMN external_id VARCHAR(200);
ALTER TABLE alert ADD COLUMN details JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE alert ADD COLUMN psa_ticket_id VARCHAR(200);
ALTER TABLE alert ADD COLUMN remediation_status VARCHAR(30) NOT NULL DEFAULT 'not_requested';
CREATE UNIQUE INDEX ix_alert_source_external ON alert(source, external_id);
CREATE TABLE alert_rule (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  name VARCHAR(200) NOT NULL,
  min_severity VARCHAR(20) NOT NULL DEFAULT 'medium',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  suppress_minutes INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_alert_rule_organization ON alert_rule(organization_id);
