CREATE TABLE client (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  name VARCHAR(200) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_client_organization_name UNIQUE (organization_id, name)
);
CREATE INDEX ix_client_organization_id ON client(organization_id);
ALTER TABLE client_tenant ADD COLUMN client_id VARCHAR(36) REFERENCES client(id);
CREATE INDEX ix_client_tenant_client_id ON client_tenant(client_id);
CREATE TABLE staff_group (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  name VARCHAR(100) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_staff_group_organization_name UNIQUE (organization_id, name)
);
CREATE INDEX ix_staff_group_organization_id ON staff_group(organization_id);
CREATE TABLE staff_group_membership (
  id VARCHAR(36) PRIMARY KEY,
  staff_group_id VARCHAR(36) NOT NULL REFERENCES staff_group(id) ON DELETE CASCADE,
  staff_user_id VARCHAR(36) NOT NULL REFERENCES staff_user(id) ON DELETE CASCADE,
  assigned_by VARCHAR(36) NOT NULL REFERENCES staff_user(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_staff_group_membership UNIQUE (staff_group_id, staff_user_id)
);
CREATE INDEX ix_staff_group_membership_group_id ON staff_group_membership(staff_group_id);
CREATE INDEX ix_staff_group_membership_user_id ON staff_group_membership(staff_user_id);
