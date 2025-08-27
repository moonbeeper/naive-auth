-- Add up migration script here
alter table users
alter column email set not null;