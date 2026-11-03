-- +goose Up
-- Tables are unqualified: the connection's search_path is the `auth` schema
-- (see migrations.Open), which also holds goose's version table.
CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text        NOT NULL UNIQUE CHECK (email = lower(email)),
    password_hash text        NOT NULL,
    name          text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    failed_logins integer     NOT NULL DEFAULT 0,
    locked_until  timestamptz
);

CREATE TABLE refresh_tokens (
    token_hash bytea       PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    user_agent text        NOT NULL DEFAULT '',
    ip         text        NOT NULL DEFAULT ''
);

CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);

CREATE TABLE signing_key (
    id              smallint    PRIMARY KEY CHECK (id = 1),
    kid             text        NOT NULL,
    private_key_enc bytea       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE signing_key;
DROP TABLE refresh_tokens;
DROP TABLE users;
