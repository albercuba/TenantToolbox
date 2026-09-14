CREATE TABLE tenant_device_snapshot (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  graph_id VARCHAR(100) NOT NULL,
  device_name VARCHAR(200) NOT NULL,
  operating_system VARCHAR(100),
  compliance_state VARCHAR(50),
  last_sync_at TIMESTAMPTZ,
  synced_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_tenant_device_snapshot_tenant ON tenant_device_snapshot(client_tenant_id);
