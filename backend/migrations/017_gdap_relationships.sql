CREATE TABLE IF NOT EXISTS gdap_relationship (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL REFERENCES organization(id),
    client_tenant_id VARCHAR(36) REFERENCES client_tenant(id) ON DELETE SET NULL,
    customer_tenant_id VARCHAR(36) NOT NULL,
    graph_id VARCHAR(100),
    display_name VARCHAR(200) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    approval_url TEXT,
    details JSON NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_gdap_relationship_organization_id ON gdap_relationship(organization_id);
CREATE INDEX IF NOT EXISTS ix_gdap_relationship_client_tenant_id ON gdap_relationship(client_tenant_id);
CREATE INDEX IF NOT EXISTS ix_gdap_relationship_customer_tenant_id ON gdap_relationship(customer_tenant_id);
