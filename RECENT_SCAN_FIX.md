# Recent Scan Table Fix - Unified ZAP & Proxy Results

## Problem Description
The Recent Scan table on the UI plugin had conflicting behavior:
- **When proxy is DOWN**: Shows only ZAP database results ✓
- **When proxy is UP**: Shows only proxy results ✗ (ZAP results hidden)
- **Should show**: Both ZAP AND proxy results, unified and sorted by timestamp

## Root Cause
In `lib.php`, function `local_security_dashboard_get_logs()` used conditional logic:
```php
if (empty($logs)) {
    // Get ZAP scans - only if proxy has NO data
}
```

This meant:
- Proxy returns data → Stop, never check ZAP database ❌
- Proxy fails → Fallback to ZAP only

## Solution Implemented

### Code Changes
**File**: `moodle-plugin/lib.php`
**Function**: `local_security_dashboard_get_logs()`

#### Original Logic (WRONG):
1. Fetch from proxy endpoint → If data found, stop
2. Only try ZAP if proxy has NO data

#### New Logic (CORRECT):
1. **ALWAYS** fetch from proxy endpoint
2. **ALWAYS** fetch from ZAP database
3. **MERGE** both arrays
4. **SORT** by timestamp descending
5. **LIMIT** to requested number of results

### Key Changes:
```php
// Before: Single $logs array  
$logs = [];

// After: Separate tracking for sources
$logs = [];
$proxy_logs = [];
$zap_logs = [];

// Key fix: Always fetch both
$proxy_logs = fetch_proxy_data();  // Always happens
$zap_logs = fetch_zap_database();  // Always happens, not just fallback

// Merge and sort
$logs = array_merge($proxy_logs, $zap_logs);
usort($logs, function($a, $b) {
    return strtotime($b['timestamp']) - strtotime($a['timestamp']);
});
```

## Benefits Now:

### 1. Complete Visibility
- See ZAP scans AND proxy scans in one unified view
- No more "missing" results when proxy is online

### 2. Better Timeline
- All scans ordered chronologically
- Easy to see which tool found what issue

### 3. Proper Source Attribution
Each result clearly shows:
- `[ZAP]` badge for zero-trust scanner results
- `[PROXY]` badge for authenticated scanner results

### 4. Works Regardless of Proxy Status
- If proxy down: Shows ZAP results
- If proxy up: Shows both

## Example Output

```
Timeline of Recent Scans:
1. [PROXY] authenticated_scan - 10 findings
2. [ZAP] full_site_scan - 8 findings  
3. [PROXY] native_auth - 5 findings
4. [ZAP] api_scan - 3 findings
```

## Testing Instructions

### Test Case 1: Proxy Running + ZAP Data Present
1. Start proxy: `cd proxy && python3 app.py`
2. Create ZAP scan results in database
3. View Recent Scans in Moodle UI
4. **Expected**: Both ZAP and proxy results visible

### Test Case 2: Proxy Down + ZAP Data Present
1. Stop proxy service
2. View Recent Scans in Moodle UI
3. **Expected**: ZAP results still visible

### Test Case 3: Both Sources Populated
1. Run multiple scans with both tools
2. View Recent Scans
3. **Expected**: All results in chronological order with badges

## Technical Details

### Data Flow
```
index.php (UI)
    ↓
lib.php: get_logs()
    ├→ Fetch proxy/ml/dashboard/recent-scans (NEW endpoint)
    ├→ Fallback: /logs endpoint (OLD endpoint)
    ├→ Fetch local_security_scans from DB
    ↓
Merge & sort results
    ↓
Return unified array
    ↓
index.php displays with badges
```

### Modified Components
- ✅ `moodle-plugin/lib.php`: `local_security_dashboard_get_logs()`
- ✅ No changes needed to index.php or other files (already compatible)
- ✅ No database changes required
- ✅ Backward compatible with existing data

## Logging
Enhanced error logs for troubleshooting:
```
[lib.php] ===== MERGED SOURCES =====
[lib.php] Proxy logs: 5
[lib.php] ZAP logs: 3
[lib.php] Total logs collected: 8
```

## Performance Impact
- **Minimal**: Fetches same data, just better organized
- Both queries run in parallel logic (attempted)
- Results limited by `$limit` parameter (default 100)

## Next Steps (Optional Enhancements)
- [ ] Add filter buttons: "Show ZAP only", "Show Proxy only"
- [ ] Add scan source statistics
- [ ] Add export functionality
- [ ] Add color coding for severity levels

---
**Status**: ✅ COMPLETE AND TESTED
**Date**: April 2, 2026
**Files Modified**: 1 (lib.php)
