-- Add up migration script here
create table if not exists users (
    id UUID not null primary key,
    login varchar(32) not null unique,
    display_name varchar(32) not null,
    email varchar(256),
    email_verified boolean not null default false,
    password_hash text,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

create table if not exists sessions (
    id UUID not null primary key,
    user_id UUID not null references users(id) on delete cascade,
    name varchar(32) not null,
    active_expires_at TIMESTAMPTZ NOT NULL,
    inactive_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)