DELETE FROM push_registrations WHERE provider = 'apns';

ALTER TABLE push_registrations
    DROP CONSTRAINT IF EXISTS push_registrations_provider_check;

ALTER TABLE push_registrations
    ADD CONSTRAINT push_registrations_provider_check
    CHECK (provider IN ('fcm', 'unifiedpush', 'embedded_socket'));

ALTER TABLE push_registrations
    DROP COLUMN IF EXISTS apns_device_token;
