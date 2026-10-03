BEGIN;
CREATE TABLE IF NOT EXISTS users (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS windows_devices (id uuid PRIMARY KEY, data jsonb NOT NULL,
  CHECK (NOT (data->'jwk' ? 'd')));
CREATE TABLE IF NOT EXISTS android_devices (id uuid PRIMARY KEY, data jsonb NOT NULL,
  CHECK (NOT (data->'approvalJwk' ? 'd') AND NOT (data->'identityJwk' ? 'd')));
CREATE TABLE IF NOT EXISTS device_pairings (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS pairing_sessions (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS authentication_requests (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS unique_request_nonce ON authentication_requests ((data->>'nonce'));
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_request ON authentication_requests ((data->>'pairingId'))
  WHERE data->>'state' = 'pending';
CREATE TABLE IF NOT EXISTS authentication_events (id uuid PRIMARY KEY, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS pairing_windows ON device_pairings ((data->>'windowsDeviceId'));
CREATE INDEX IF NOT EXISTS request_phone ON authentication_requests ((data->>'androidDeviceId'));
COMMIT;
