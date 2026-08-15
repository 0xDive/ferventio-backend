ALTER TABLE push_registrations
    ADD COLUMN IF NOT EXISTS apns_device_token TEXT NOT NULL DEFAULT '';

ALTER TABLE push_registrations
    DROP CONSTRAINT IF EXISTS push_registrations_provider_check;

ALTER TABLE push_registrations
    ADD CONSTRAINT push_registrations_provider_check
    CHECK (provider IN ('fcm', 'unifiedpush', 'embedded_socket', 'apns'));
