-- 1.7.2: remember which ACME directory issued a certificate, so switching
-- from Let's Encrypt staging to production (or back) re-issues instead of
-- reusing the untrusted certificate. Existing rows are backfilled on API
-- boot from the certificate's issuer name.
ALTER TABLE certificates ADD COLUMN acme_directory TEXT NOT NULL DEFAULT '';
