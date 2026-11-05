ALTER TABLE push_registrations
    ADD COLUMN IF NOT EXISTS notification_channel_muted_until_epoch_millis JSONB NOT NULL DEFAULT '{}'::jsonb;
