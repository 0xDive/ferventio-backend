ALTER TABLE push_registrations
    DROP COLUMN IF EXISTS notification_channel_muted_until_epoch_millis;
