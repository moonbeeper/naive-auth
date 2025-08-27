-- Add down migration script here
alter table users
alter column email type varchar(256),
alter column display_name set not null;