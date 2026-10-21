-- Commercial licensing is gone. Drop the sealed key, lease, and instance id
-- so they are not left at rest. Host WAF, CrowdSec, and GeoIP settings stay.
DELETE FROM settings WHERE key LIKE 'license.%';
