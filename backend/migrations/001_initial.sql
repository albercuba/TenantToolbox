CREATE TABLE organization (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE staff_user (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  email VARCHAR(320) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'tech'
);
CREATE TABLE client_tenant (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
  tenant_id VARCHAR(36) NOT NULL UNIQUE,
  display_name VARCHAR(200) NOT NULL,
  connection_status VARCHAR(30) NOT NULL DEFAULT 'pending',
  last_connected_at TIMESTAMPTZ,
  last_error TEXT
);
CREATE TABLE tenant_credential (
  id VARCHAR(36) PRIMARY KEY,
  client_tenant_id VARCHAR(36) NOT NULL UNIQUE REFERENCES client_tenant(id) ON DELETE CASCADE,
  encrypted_refresh_token TEXT NOT NULL,
  encrypted_access_token TEXT,
  access_token_expires_at TIMESTAMPTZ
);
CREATE INDEX ix_staff_user_organization_id ON staff_user(organization_id);
CREATE INDEX ix_client_tenant_organization_id ON client_tenant(organization_id);
