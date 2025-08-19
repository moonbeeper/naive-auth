-- Add up migration script here
alter table sessions
add sudo_enabled_at TIMESTAMPTZ;