CREATE TABLE discovered_app (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  graph_id VARCHAR(100) NOT NULL,
  display_name VARCHAR(200) NOT NULL,
  publisher VARCHAR(200),
  permission_scopes JSONB NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  last_seen_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX ix_discovered_app_tenant_graph ON discovered_app(client_tenant_id, graph_id);
