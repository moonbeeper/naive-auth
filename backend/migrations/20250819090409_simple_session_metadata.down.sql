-- Add down migration script here
alter table sessions
drop os,
drop browser;