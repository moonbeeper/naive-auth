-- Add up migration script here
alter table users
add totp_secret varchar(32), -- copies github's only one authenticator app
add totp_recovery_secret varchar(32), -- runtime waaaahooo
add totp_recovery_codes int default 0 not null;