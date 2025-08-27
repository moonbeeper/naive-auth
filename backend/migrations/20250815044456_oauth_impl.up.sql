-- Add up migration script here
create table if not exists oauth_applications (
    id varchar(32) not null primary key,
    name varchar(32) not null,
    description text,
    key varchar(97) not null,
    scopes bigint not null default 0,
    callback_url text not null,
    created_by UUID not null references users(id) on delete cascade,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

create table if not exists oauth_authorizations (
    id UUID not null primary key,
    app varchar(32) not null references oauth_applications(id) on delete cascade,
    user_id UUID not null references users(id) on delete cascade,
    scopes bigint not null default 0,
    token varchar(64) not null,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);