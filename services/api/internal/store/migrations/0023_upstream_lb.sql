-- 1.7.2: upstream selection policy and active HTTP health checks.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS lb_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS health_path TEXT NOT NULL DEFAULT '';
