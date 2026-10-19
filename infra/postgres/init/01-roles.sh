#!/bin/sh
# Runs once, on first initialisation of an empty data directory.
#
# Roles:
#   postgres  - superuser, used only for this bootstrap (password: db_admin_password)
#   df_owner  - owns the database and schema; used only by migrations
#   df_app    - runtime role for api/worker/scheduler: DML only, no DDL, no TRUNCATE,
#               and no UPDATE/DELETE on audit_log (revoked by the first migration)
#
# Passwords are read from Docker secrets with psql's \set + backticks, so they are
# never placed on a command line or in the environment.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
\set owner_pw `cat /run/secrets/db_owner_password`
\set app_pw `cat /run/secrets/db_app_password`
CREATE ROLE df_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE df_app LOGIN PASSWORD :'app_pw';
CREATE DATABASE doctor_firewall OWNER df_owner;
REVOKE ALL ON DATABASE doctor_firewall FROM PUBLIC;
GRANT CONNECT ON DATABASE doctor_firewall TO df_owner, df_app;
\connect doctor_firewall
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO df_owner;
GRANT USAGE ON SCHEMA public TO df_app;
ALTER DEFAULT PRIVILEGES FOR ROLE df_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO df_app;
ALTER DEFAULT PRIVILEGES FOR ROLE df_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO df_app;
SQL
