CREATE TABLE IF NOT EXISTS vault_requests (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS vault_nonce_unique ON vault_requests ((data->>'nonce'));
CREATE INDEX IF NOT EXISTS vault_phone_pending ON vault_requests ((data->>'androidDeviceId')) WHERE data->>'state'='pending';
CREATE INDEX IF NOT EXISTS vault_windows_pending ON vault_requests ((data->>'windowsDeviceId')) WHERE data->>'state'='pending';
