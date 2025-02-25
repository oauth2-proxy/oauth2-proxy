-- migrate:up
CREATE TABLE users (
    id text PRIMARY KEY,
    email text NOT NULL UNIQUE,
    name text,
    provider text NOT NULL,
    provider_user_id text NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    enabled BOOLEAN DEFAULT TRUE,
    role text NOT NULL DEFAULT 'user',
    permissions JSONB NOT NULL DEFAULT '{}',
    UNIQUE(provider, provider_user_id)
);

-- migrate:down
DROP TABLE users;
