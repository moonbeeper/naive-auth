-- Add down migration script here
alter table sessions
drop sudo_enabled_at;