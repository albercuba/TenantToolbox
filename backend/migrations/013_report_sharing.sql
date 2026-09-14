ALTER TABLE report ADD COLUMN public_token_hash VARCHAR(128);
ALTER TABLE report ADD COLUMN public_expires_at TIMESTAMPTZ;
CREATE UNIQUE INDEX ix_report_public_token_hash ON report(public_token_hash);
