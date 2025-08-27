-- Add up migration script here
alter table users
alter column email type varchar(320),
alter column display_name drop not null;
