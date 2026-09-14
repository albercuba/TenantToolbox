CREATE TABLE tenant_user_snapshot (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  graph_id VARCHAR(100) NOT NULL,
  display_name VARCHAR(200) NOT NULL,
  user_principal_name VARCHAR(320) NOT NULL,
  account_enabled BOOLEAN,
  synced_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_tenant_user_snapshot_tenant ON tenant_user_snapshot(client_tenant_id);
CREATE TABLE tenant_license_snapshot (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  sku_id VARCHAR(100) NOT NULL,
  sku_part_number VARCHAR(200) NOT NULL,
  consumed_units INTEGER NOT NULL DEFAULT 0,
  enabled_units INTEGER NOT NULL DEFAULT 0,
  synced_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_tenant_license_snapshot_tenant ON tenant_license_snapshot(client_tenant_id);
CREATE TABLE tenant_secure_score_snapshot (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  score FLOAT,
  max_score FLOAT,
  control_states JSONB NOT NULL,
  synced_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_tenant_secure_score_snapshot_tenant ON tenant_secure_score_snapshot(client_tenant_id);
