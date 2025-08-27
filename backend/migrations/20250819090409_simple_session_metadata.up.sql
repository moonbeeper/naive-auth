-- Add up migration script here
alter table sessions
add os text not null default 'unknown',
add browser text not null default 'unknown';