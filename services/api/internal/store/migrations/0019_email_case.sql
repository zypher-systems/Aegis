-- 1.7.2: emails are compared case-insensitively. Lower-case existing rows and
-- enforce uniqueness on the lower-cased value, unless two rows already differ
-- only by case (then the old exact-match uniqueness stays and the API still
-- lower-cases new input).
UPDATE users SET email = lower(email)
WHERE email <> lower(email)
  AND NOT EXISTS (SELECT 1 FROM users u2 WHERE lower(u2.email) = lower(users.email) AND u2.id <> users.id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT lower(email) FROM users GROUP BY lower(email) HAVING count(*) > 1) THEN
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));
  END IF;
END $$;
