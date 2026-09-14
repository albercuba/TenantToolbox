CREATE TABLE user_group (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  name VARCHAR(200) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, name)
);
CREATE INDEX ix_user_group_organization ON user_group(organization_id);

CREATE TABLE group_membership (
  id VARCHAR(36) PRIMARY KEY,
  user_group_id VARCHAR(36) NOT NULL REFERENCES user_group(id) ON DELETE CASCADE,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  graph_user_id VARCHAR(100) NOT NULL,
  added_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_group_id, client_tenant_id, graph_user_id)
);
CREATE INDEX ix_group_membership_group ON group_membership(user_group_id);
CREATE INDEX ix_group_membership_tenant ON group_membership(client_tenant_id);

CREATE TABLE distribution_list (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  graph_id VARCHAR(100),
  display_name VARCHAR(200) NOT NULL,
  email VARCHAR(320) NOT NULL,
  created_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, client_tenant_id, email)
);
CREATE INDEX ix_distribution_list_organization ON distribution_list(organization_id);
CREATE INDEX ix_distribution_list_tenant ON distribution_list(client_tenant_id);

CREATE TABLE offboarding_workflow (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  graph_user_id VARCHAR(100) NOT NULL,
  state VARCHAR(30) NOT NULL DEFAULT 'pending',
  completed_steps JSON NOT NULL DEFAULT '[]',
  created_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(client_tenant_id, graph_user_id)
);
CREATE INDEX ix_offboarding_workflow_tenant ON offboarding_workflow(client_tenant_id);

CREATE TABLE offboarding_history (
  id VARCHAR(36) PRIMARY KEY,
  workflow_id VARCHAR(36) NOT NULL REFERENCES offboarding_workflow(id) ON DELETE CASCADE,
  action VARCHAR(50) NOT NULL,
  status VARCHAR(30) NOT NULL,
  details JSON NOT NULL DEFAULT '{}',
  actor_id VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_offboarding_history_workflow ON offboarding_history(workflow_id);

CREATE TABLE device_compliance_policy_template (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  name VARCHAR(200) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  definition JSON NOT NULL,
  is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(organization_id, name)
);
CREATE INDEX ix_device_compliance_policy_template_organization ON device_compliance_policy_template(organization_id);

CREATE TABLE device_compliance_policy_assignment (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL REFERENCES client_tenant(id) ON DELETE CASCADE,
  template_id VARCHAR(36) NOT NULL REFERENCES device_compliance_policy_template(id) ON DELETE CASCADE,
  assigned_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(client_tenant_id, template_id)
);
CREATE INDEX ix_device_compliance_policy_assignment_tenant ON device_compliance_policy_assignment(client_tenant_id);
