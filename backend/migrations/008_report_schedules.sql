ALTER TABLE organization ADD COLUMN branding_color VARCHAR(20) NOT NULL DEFAULT '#2490ef';
ALTER TABLE organization ADD COLUMN branding_logo_url TEXT;
CREATE TABLE report_schedule (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  cadence VARCHAR(20) NOT NULL,
  recipient_email VARCHAR(320) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  next_run_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_report_schedule_due ON report_schedule(enabled, next_run_at);
