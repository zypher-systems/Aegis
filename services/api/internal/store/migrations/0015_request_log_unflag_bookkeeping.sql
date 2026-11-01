-- 1.7.1: Detect mode marked every request "flagged" with the last CRS rule
-- that ran, usually a bookkeeping rule such as 980014 (a paranoia-level skip
-- that matches every request). Real detections are CRS rules 911000-948999;
-- clear the flag on the rest so the Flagged filter shows only real matches.

UPDATE request_log
SET waf_action = '',
    waf_rule_id = '',
    event = event - 'waf_action' - 'waf_rule_id' - 'waf_score' - 'waf_matches'
WHERE waf_action = 'detect'
  AND block_stage = ''
  AND waf_rule_id !~ '^9(1[1-9]|[23][0-9]|4[0-8])[0-9]{3}$';
