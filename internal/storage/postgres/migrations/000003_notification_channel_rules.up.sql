ALTER TABLE push_registrations
    ADD COLUMN IF NOT EXISTS notification_channel_rules JSONB NOT NULL DEFAULT '{}'::jsonb;
