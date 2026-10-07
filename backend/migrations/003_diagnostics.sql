CREATE TABLE IF NOT EXISTS diagnostic_logs(id uuid PRIMARY KEY,data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS diagnostics_device_time ON diagnostic_logs((data->>'windowsDeviceId'),((data->>'timestamp')::bigint) DESC);
CREATE INDEX IF NOT EXISTS remote_phone_lookup ON remote_offers((data->>'androidDeviceId'));
