#!/bin/bash

# Check ZAP scans in database
mysql -h localhost -u root -proot moodle_db << EOF
SELECT 
  scan_id, 
  scan_type, 
  target_url, 
  total_findings, 
  high_count, 
  medium_count, 
  low_count, 
  FROM_UNIXTIME(timecreated) as created 
FROM mdl_local_security_scans 
ORDER BY timecreated DESC 
LIMIT 5;
EOF
