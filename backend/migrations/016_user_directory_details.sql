ALTER TABLE tenant_user_snapshot ADD COLUMN department VARCHAR(200);
ALTER TABLE tenant_user_snapshot ADD COLUMN license_types JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE tenant_user_snapshot ADD COLUMN groups JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE tenant_user_snapshot ADD COLUMN mfa_settings VARCHAR(100) NOT NULL DEFAULT 'Unavailable';
