CREATE TABLE IF NOT EXISTS push_registrations (
    installation_id TEXT PRIMARY KEY,
    device_secret_hash TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('fcm', 'unifiedpush', 'embedded_socket')),
    firebase_installation_id TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    p256dh TEXT NOT NULL DEFAULT '',
    auth TEXT NOT NULL DEFAULT '',
    app_version TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT 'android',
    user_id TEXT NOT NULL DEFAULT '',
    user_login TEXT NOT NULL DEFAULT '',
    channel_ids TEXT[] NOT NULL DEFAULT '{}',
    moderator_channel_ids TEXT[] NOT NULL DEFAULT '{}',
    notification_rules TEXT[] NOT NULL DEFAULT '{}',
    highlight_phrases TEXT[] NOT NULL DEFAULT '{}',
    selected_user_logins TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS push_registrations_user_id_idx
    ON push_registrations (user_id)
    WHERE user_id <> '';
CREATE INDEX IF NOT EXISTS push_registrations_updated_at_idx
    ON push_registrations (updated_at DESC);

CREATE TABLE IF NOT EXISTS auth_credentials (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    access_nonce TEXT NOT NULL,
    access_ciphertext TEXT NOT NULL,
    refresh_nonce TEXT NOT NULL,
    refresh_ciphertext TEXT NOT NULL,
    access_expires_at TIMESTAMPTZ NOT NULL,
    last_validated_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_credentials_user_id_idx
    ON auth_credentials (user_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES auth_credentials(id) ON DELETE CASCADE,
    installation_id TEXT NOT NULL,
    device_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_installation_id_uidx
    ON auth_sessions (installation_id);
CREATE INDEX IF NOT EXISTS auth_sessions_credential_id_idx
    ON auth_sessions (credential_id);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx
    ON auth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS auth_pending (
    state_hash TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    device_hash TEXT NOT NULL,
    app_callback_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_pending_installation_device_uidx
    ON auth_pending (installation_id, device_hash);
CREATE INDEX IF NOT EXISTS auth_pending_expires_at_idx
    ON auth_pending (expires_at);

CREATE TABLE IF NOT EXISTS auth_handoffs (
    code_hash TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES auth_credentials(id) ON DELETE CASCADE,
    installation_id TEXT NOT NULL,
    device_hash TEXT NOT NULL,
    app_callback_uri TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_handoffs_installation_device_uidx
    ON auth_handoffs (installation_id, device_hash);
CREATE INDEX IF NOT EXISTS auth_handoffs_credential_id_idx
    ON auth_handoffs (credential_id);
CREATE INDEX IF NOT EXISTS auth_handoffs_expires_at_idx
    ON auth_handoffs (expires_at);

CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    notification_type TEXT NOT NULL DEFAULT '',
    notification_title TEXT NOT NULL,
    notification_body TEXT NOT NULL,
    notification_channel_id TEXT NOT NULL DEFAULT '',
    notification_channel_login TEXT NOT NULL DEFAULT '',
    notification_message_id TEXT NOT NULL DEFAULT '',
    notification_actor_id TEXT NOT NULL DEFAULT '',
    notification_actor_login TEXT NOT NULL DEFAULT '',
    notification_actor_display_name TEXT NOT NULL DEFAULT '',
    notification_destination TEXT NOT NULL DEFAULT '',
    notification_silent BOOLEAN NOT NULL DEFAULT FALSE,
    notification_created_at_epoch_millis BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'acked', 'dead')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ,
    acked_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS deliveries_installation_event_uidx
    ON deliveries (installation_id, event_id);
CREATE INDEX IF NOT EXISTS deliveries_pending_idx
    ON deliveries (installation_id, available_at, created_at)
    WHERE status IN ('pending', 'sent');
CREATE INDEX IF NOT EXISTS deliveries_created_at_idx
    ON deliveries (created_at DESC);
CREATE INDEX IF NOT EXISTS deliveries_cleanup_idx
    ON deliveries (status, acked_at, created_at);

CREATE TABLE IF NOT EXISTS eventsub_seen (
    message_id TEXT PRIMARY KEY,
    seen_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS eventsub_seen_seen_at_idx
    ON eventsub_seen (seen_at);

CREATE TABLE IF NOT EXISTS eventsub_inbox (
    message_id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL DEFAULT '',
    subscription_id TEXT NOT NULL DEFAULT '',
    subscription_type TEXT NOT NULL DEFAULT '',
    subscription_version TEXT NOT NULL DEFAULT '',
    subscription_status TEXT NOT NULL DEFAULT '',
    subscription_condition JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL CHECK (status IN ('pending', 'dead')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    last_attempt_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS eventsub_inbox_pending_idx
    ON eventsub_inbox (available_at, received_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS eventsub_inbox_cleanup_idx
    ON eventsub_inbox (status, received_at, expires_at);

CREATE TABLE IF NOT EXISTS channel_notification_states (
    channel_id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    category_name TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_records (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '',
    installation_id TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL DEFAULT '',
    channel_id TEXT NOT NULL DEFAULT '',
    event_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_records_timestamp_idx
    ON audit_records (timestamp DESC);
CREATE INDEX IF NOT EXISTS audit_records_action_idx
    ON audit_records (action, timestamp DESC);

CREATE TABLE IF NOT EXISTS settings_sync_snapshots (
    user_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by_installation_id TEXT NOT NULL,
    app_version TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (user_id, revision)
);

CREATE INDEX IF NOT EXISTS settings_sync_snapshots_current_idx
    ON settings_sync_snapshots (user_id, revision DESC);
