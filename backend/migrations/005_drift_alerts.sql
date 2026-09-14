CREATE TABLE drift_event (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  baseline_template_id VARCHAR(36) NOT NULL REFERENCES baseline_template(id),
  differences JSONB NOT NULL,
  resolved_at TIMESTAMPTZ,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_drift_event_tenant_detected ON drift_event(client_tenant_id, detected_at DESC);
CREATE TABLE alert (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  drift_event_id VARCHAR(36) REFERENCES drift_event(id) ON DELETE SET NULL,
  severity VARCHAR(20) NOT NULL,
  title VARCHAR(200) NOT NULL,
  message TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);
CREATE INDEX ix_alert_tenant_status ON alert(client_tenant_id, status);
