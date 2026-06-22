-- 6. Revoke CREATE on public schema
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- 7. Remove unnecessary superuser privileges
--- Restrict your application user
ALTER ROLE hips_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

--- Ensure login only if needed
ALTER ROLE hips_app LOGIN;