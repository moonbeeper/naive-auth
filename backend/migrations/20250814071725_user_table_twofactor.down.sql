-- Add down migration script here
alter table users
drop totp_secret,
drop totp_recovery_secret,
drop totp_recovery_codes;