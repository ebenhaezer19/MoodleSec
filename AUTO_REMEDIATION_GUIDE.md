# Auto-Remediation & Whitelist Learning Guide

## 🎯 Fitur Baru v1.3.0

Sekarang phishing scanner memiliki 3 peningkatan MAJOR yang menjawab pertanyaan Anda:

### ✅ 1. Direct Content Links - "Kita tidak tahu URL mana yang harus diperbaiki"

**PROBLEM SOLVED**: Setiap finding sekarang punya link langsung ke content yang bermasalah!

| Content Type | Link Mengarah Ke | Contoh |
|--------------|------------------|---------|
| **user_profile** | Profile edit page user tersebut | `/user/profile.php?id=123` |
| **forum_post** | Post spesifik di forum discussion | `/mod/forum/discuss.php?d=45#p789` |
| **comment** | Context page dengan anchor ke comment | `/mod/assign/view.php?id=X#comment-Y` |

**Cara Pakai:**
1. Lihat finding di historical table
2. Kolom "Location" ada tombol **"View Content"**  
3. Click → Langsung buka tab baru ke content tersebut
4. Review apakah benar phishing
5. Kembali ke scanner → Pilih action

---

### ✅ 2. Auto-Remediation - "Cari manual atau ada tombol otomatis?"

**PROBLEM SOLVED**: Tidak perlu cari manual! Ada tombol otomatis untuk menghapus/quarantine!

#### **Delete Button (🗑️ Merah)**
Menghapus content **secara permanen**:

| Content Type | Apa Yang Dilakukan |
|--------------|-------------------|
| User Profile | Clear field `description` (bio kosong) |
| Forum Post | Call `forum_delete_post()` (post hilang) |
| Comment | Delete record dari database |

**Workflow:**
```
Click "Delete" → Confirm dialog → Content dihapus → Finding auto-marked "resolved"
```

#### **Quarantine Button (🚫 Orange)**  
Hide content **tanpa menghapus** (soft delete):

| Content Type | Apa Yang Dilakukan |
|--------------|-------------------|
| User Profile | Suspend user account (bisa di-unsuspend) |
| Forum Post | Set `deleted=1` flag (hidden tapi masih di DB) |
| Comment | Replace content dengan "[Content hidden by admin - potential phishing]" |

**Workflow:**
```
Click "Quarantine" → Confirm dialog → Content di-hide → Finding auto-marked "resolved"
```

**Keuntungan Quarantine:**
- Reversible (bisa dikembalikan)
- Investigasi lebih lanjut masih mungkin
- Data forensik tersimpan

---

### ✅ 3. Whitelist Learning - "Apakah false positive dipelajari otomatis?"

**PROBLEM SOLVED**: YES! System otomatis belajar dari false positive Anda!

#### **Mekanisme Learning:**

**Step 1: Mark as False Positive**
```
Admin click "False Positive (Whitelist)" button
↓
System extract domain dari URL
↓
Auto-insert ke whitelist table
```

**Step 2: Future Scans**
```
Scanner deteksi URL baru
↓
Check: Apakah domain ada di whitelist?
↓
IF YES: Skip detection (tidak disimpan ke findings)
IF NO: Proceed dengan detection
```

**Example:**
1. Scan deteksi `https://university-official.edu/announcement`
2. Admin review: "Ini official university website, bukan phishing!"
3. Click "False Positive (Whitelist)"
4. Domain `university-official.edu` masuk whitelist
5. **Future scans**: Semua URL dari `university-official.edu` auto-skip
6. **Tidak akan muncul lagi** di findings!

---

## 🗄️ Database Schema Baru

### Table: `mdl_local_security_phishing` (Updated)

**New Field:**
```sql
content_url TEXT    -- Direct URL to problematic content
```

### Table: `mdl_local_security_phishing_whitelist` (New)

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| whitelist_type | VARCHAR(20) | domain, user, url_pattern |
| whitelist_value | TEXT | Domain name, user ID, or regex |
| reason | TEXT | Why whitelisted |
| source | VARCHAR(50) | manual, auto_from_false_positive |
| created_by | INT | Admin who added |
| timecreated | INT | Unix timestamp |

**Examples:**

```sql
-- Auto-whitelisted domain
INSERT INTO mdl_local_security_phishing_whitelist VALUES (
    1, 'domain', 'university.edu', 
    'Auto-whitelisted from false positive finding #123',
    'auto_from_false_positive', 2, 1736640000
);

-- Manually whitelisted user (trusted admin)
INSERT INTO mdl_local_security_phishing_whitelist VALUES (
    2, 'user', '456',
    'Site administrator - trusted',
    'manual', 2, 1736640000
);

-- URL pattern whitelist
INSERT INTO mdl_local_security_phishing_whitelist VALUES (
    3, 'url_pattern', 'docs.google.com/.*',
    'Official Google Docs links',
    'manual', 2, 1736640000
);
```

---

## 🎨 New UI Components

### Historical Findings Table (Enhanced)

**Before:**
```
| Date | Type | User | Risk | URL | Status | Actions |
```

**After:**
```
| Date | Type | User | Risk | Location | Status | Actions |
                                   ↑ NEW       ↑ ENHANCED
                              "View Content"   More actions
```

### Action Buttons (Enhanced)

**OLD (2 buttons):**
- ✅ Resolve
- ℹ️ False Positive

**NEW (6 buttons in 2 rows):**

**Row 1 - Destructive Actions:**
- 🗑️ **Delete** (red) - Permanent removal
- 🚫 **Quarantine** (orange) - Hide content

**Row 2 - Status Actions:**
- ✅ **Mark Resolved** (green) - Manual fix
- ℹ️ **False Positive (Whitelist)** (gray) - Learn from mistake

---

## 🚀 Deployment Guide

### Upgrade Steps (Linux Server)

```bash
# 1. Pull latest code
cd ~/TA/adaptive-moodle-security/MoodleSec
git pull origin main

# 2. Copy plugin files
sudo cp -r moodle-plugin/* /var/www/html/moodle/public/local/security_dashboard/
sudo chown -R www-data:www-data /var/www/html/moodle/public/local/security_dashboard/

# 3. Database upgrade (creates whitelist table + adds content_url field)
sudo -u www-data php /var/www/html/moodle/public/admin/cli/upgrade.php

# 4. Clear cache
sudo -u www-data php /var/www/html/moodle/public/admin/cli/purge_caches.php
```

### Verify Upgrade

```sql
-- Check new field exists
DESCRIBE mdl_local_security_phishing;
-- Should show: content_url TEXT

-- Check new table exists  
DESCRIBE mdl_local_security_phishing_whitelist;
-- Should return 8 columns

-- Check whitelist is empty (fresh install)
SELECT COUNT(*) FROM mdl_local_security_phishing_whitelist;
-- Should return 0
```

---

## 📖 User Workflows

### Workflow 1: Review & Delete Phishing

```
1. Login as admin
2. Go to: Site Administration → Security Dashboard → Phishing Scanner
3. See "Recent Phishing Detections" table
4. Find CRITICAL finding
5. Click "View Content" button → Opens in new tab
6. Review: Confirm it's phishing
7. Close tab, return to scanner
8. Click "Delete" button → Confirm dialog
9. Content removed, finding marked "resolved"
```

**Result:** Phishing content permanently removed in 10 seconds!

---

### Workflow 2: Quarantine for Investigation

```
1. See HIGH risk finding
2. Click "View Content" → Suspicious but need confirmation
3. Click "Quarantine" → Content hidden from public
4. Investigate user behavior
5. IF malicious: Keep quarantined, suspend user
6. IF mistake: Restore content manually
```

**Result:** Fast response without permanent deletion!

---

### Workflow 3: Learn from False Positive

```
1. See finding: "https://university.edu/donate"
2. Click "View Content" → Official donation page
3. Realize: This is FALSE POSITIVE (generic "click here" text triggered detection)
4. Click "False Positive (Whitelist)" → Confirm
5. Status → false_positive
6. Domain "university.edu" added to whitelist
7. Future scans: All university.edu URLs auto-skip
```

**Result:** System learns, reduces future noise!

---

## 🧪 Testing Scenarios

### Test 1: Direct Content Link

```bash
# Create test finding
1. Add phishing link to user bio
2. Run scan → Finding detected
3. Check findings table
4. Verify "content_url" field populated
5. Click "View Content" button
6. Should open: /user/profile.php?id=X
```

### Test 2: Delete Action

```bash
# Test profile bio deletion
1. User bio contains: <a href="phishing.com">Click here</a>
2. Scanner detects → Finding #1
3. Click "Delete" button
4. Confirm dialog → Yes
5. Check user bio: Should be EMPTY
6. Check finding status: Should be "resolved"
```

### Test 3: Whitelist Learning

```bash
# Test auto-whitelist
1. Scan detects https://safe-domain.com
2. Click "False Positive (Whitelist)"
3. Query database:
   SELECT * FROM mdl_local_security_phishing_whitelist;
4. Should see: ('domain', 'safe-domain.com', 'auto_from_false_positive')
5. Add another link from safe-domain.com
6. Re-scan → Should NOT detect (whitelisted)
7. Check findings count: Should NOT increase
```

### Test 4: Quarantine Action

```bash
# Test forum post quarantine
1. Forum post contains phishing link
2. Scanner detects → Finding #2
3. Click "Quarantine"
4. Query: SELECT deleted FROM mdl_forum_posts WHERE id=X;
5. Should return: 1 (hidden)
6. View forum as student: Post should NOT appear
7. View as admin: Can see in database
```

---

## 🎛️ Configuration

### Manual Whitelist Management

**Whitelist a Domain:**
```php
// In Moodle CLI or admin page
local_security_dashboard_add_to_whitelist(
    'domain',
    'trusted-university.edu',
    'Official university domain',
    'manual'
);
```

**Whitelist a User:**
```php
// Trust a specific user (e.g., marketing team)
local_security_dashboard_add_to_whitelist(
    'user',
    '789',  // User ID
    'Marketing team - authorized to post links',
    'manual'
);
```

**Whitelist URL Pattern:**
```php
// Allow all YouTube links
local_security_dashboard_add_to_whitelist(
    'url_pattern',
    'youtube.com/watch',
    'Educational YouTube videos',
    'manual'
);
```

---

## 🔧 Advanced Features

### Whitelist Check API

```php
// Check if URL is whitelisted before saving finding
$url = 'https://example.com/page';
$user_id = 123;

if (local_security_dashboard_is_whitelisted($url, $user_id)) {
    // Skip detection, don't save to database
    return false;
}
```

**Check Order:**
1. Check user whitelist (by user_id)
2. Check domain whitelist (extract domain from URL)
3. Check URL pattern whitelist (regex match)
4. If any match → return TRUE (skip detection)

### Content URL Generation

```php
// Automatically generate direct links
$url = local_security_dashboard_get_content_url(
    'forum_post',  // Content type
    789,           // Post ID
    456            // User ID
);

// Result: "https://moodle.site/mod/forum/discuss.php?d=123#p789"
```

---

## 📊 Comparison Matrix

### Before vs After

| Feature | v1.2.0 (Before) | v1.3.0 (After) |
|---------|-----------------|----------------|
| **Finding Location** | "Type: forum_post, ID: 789" | "View Content" button → Direct link |
| **Remediation** | Manual search & delete | "Delete" button (1-click) |
| **Quarantine** | Not available | "Quarantine" button (soft delete) |
| **False Positive** | Mark status only | Mark + Auto-whitelist domain |
| **Learning** | No learning | Whitelist prevents future detection |
| **Workflow Time** | ~5 minutes per finding | ~10 seconds per finding |

---

## 🐛 Troubleshooting

### "View Content" Button Not Working

**Check:**
```sql
SELECT content_url FROM mdl_local_security_phishing WHERE id=X;
```

**If NULL:**
- Old findings (before upgrade) won't have content_url
- Re-run scan to populate field
- Or manually populate:
  ```sql
  UPDATE mdl_local_security_phishing 
  SET content_url = 'https://moodle.site/user/profile.php?id=123'
  WHERE id=X;
  ```

### Delete Action Not Working

**Check permissions:**
```bash
# User profile: Requires moodle/user:update capability
# Forum post: Requires mod/forum:deleteanypost capability
# Comment: Requires moodle/comment:delete capability
```

**Check error logs:**
```bash
tail -f /var/log/apache2/error.log
```

### Whitelist Not Working

**Verify entry exists:**
```sql
SELECT * FROM mdl_local_security_phishing_whitelist 
WHERE whitelist_type='domain' 
AND whitelist_value='example.com';
```

**Test manually:**
```php
$is_whitelisted = local_security_dashboard_is_whitelisted(
    'https://example.com/test'
);
var_dump($is_whitelisted); // Should be TRUE
```

---

## 📈 Statistics & Monitoring

### Whitelist Usage

```sql
-- Count whitelisted domains
SELECT COUNT(*) FROM mdl_local_security_phishing_whitelist 
WHERE whitelist_type='domain';

-- Auto-whitelisted vs manual
SELECT source, COUNT(*) 
FROM mdl_local_security_phishing_whitelist 
GROUP BY source;

-- Most whitelisted domains
SELECT whitelist_value, reason 
FROM mdl_local_security_phishing_whitelist 
WHERE whitelist_type='domain'
ORDER BY timecreated DESC 
LIMIT 10;
```

### Remediation Actions

```sql
-- Findings resolved by deletion
SELECT COUNT(*) FROM mdl_local_security_phishing 
WHERE status='resolved' 
AND resolved_at IS NOT NULL;

-- False positives learned
SELECT COUNT(*) FROM mdl_local_security_phishing 
WHERE status='false_positive';
```

---

## 🎓 Best Practices

### When to Use Delete vs Quarantine

**Use DELETE when:**
- ✅ Confirmed phishing (e.g., bit.ly shortener to malware)
- ✅ Spam content with no value
- ✅ Test data you created

**Use QUARANTINE when:**
- ⚠️ Suspicious but need investigation
- ⚠️ User might be compromised (not malicious)
- ⚠️ Want to preserve evidence for reporting

### Whitelist Management

**DO:**
- ✅ Whitelist official institutional domains
- ✅ Whitelist trusted marketing team users
- ✅ Review auto-whitelisted domains monthly

**DON'T:**
- ❌ Whitelist free URL shorteners (bit.ly, tinyurl)
- ❌ Whitelist newly registered domains
- ❌ Whitelist without reason documentation

---

## 🆘 Support

**Common Questions:**

**Q: Can I undo a Delete action?**  
A: No, deletion is permanent. Use Quarantine if you need reversibility.

**Q: Does whitelist sync across multiple Moodle sites?**  
A: No, whitelist is per-installation. You can export/import manually.

**Q: Can users see why their content was removed?**  
A: Not automatically. Consider manual notification or add to finding notes.

**Q: How to bulk whitelist domains?**  
A: Use SQL INSERT or create admin page with CSV upload.

---

## 📝 Version History

- **v1.3.0 (2026-01-11)**: Auto-remediation, direct links, whitelist learning
- **v1.2.0 (2026-01-11)**: Database storage, pagination, email notifications
- **v1.1.0**: Initial phishing detection

---

**Upgrade completed!** 🎉

Phishing Scanner sekarang punya:
- ✅ Direct content links (tahu URL mana yang bermasalah)
- ✅ Auto-remediation (1-click delete/quarantine)
- ✅ Whitelist learning (belajar dari false positive)
- ✅ Enhanced workflow (5 menit → 10 detik)
