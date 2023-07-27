INSERT INTO nvip2.permission (permission_name)
SELECT p.permission_name FROM nvip_old.permission AS p ORDER BY p.permission_id;

INSERT INTO nvip2.role (name)
SELECT r.name FROM nvip_old.role AS r ORDER BY r.role_id;

INSERT INTO nvip2.user (user_name, password_hash, token, token_expiration_date, first_name, last_name, role_id, email, registered_date, last_login_date)
SELECT u.user_name, u.password_hash, u.token, u.token_expiration_date, u.first_name, u.last_name, u.role_id, u.email, u.registered_date, u.last_login_date
FROM nvip_old.user AS u ORDER BY u.user_id;

INSERT INTO nvip2.userpermission (user_id, permission_id, date)
SELECT up.user_id, up.permission_id, up.date FROM nvip_old.userpermission AS up;