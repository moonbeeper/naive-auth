-- Add down migration script here
alter table users
alter column email drop not null;