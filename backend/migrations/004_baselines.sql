CREATE TABLE baseline_template (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(200) NOT NULL UNIQUE,
  description TEXT NOT NULL,
  definition JSONB NOT NULL,
  is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE tenant_baseline_assignment (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  baseline_template_id VARCHAR(36) NOT NULL REFERENCES baseline_template(id),
  assigned_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(client_tenant_id, baseline_template_id)
);
