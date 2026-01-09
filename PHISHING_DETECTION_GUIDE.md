# 🛡️ Phishing Detection - User Guide

## 📍 Lokasi Akses Phishing Scanner

### **Cara 1: Dari Dashboard Utama (PALING MUDAH)**

1. **Login sebagai Admin** ke Moodle
2. **Navigate ke:** 
   ```
   Site administration → Local plugins → Security Dashboard → Dashboard
   ```
3. **Klik tombol merah:**
   ```
   🛡️ Phishing Scanner
   ```
   
   Tombol ini berada di sebelah kanan tombol "ML Dashboard"

---

### **Cara 2: Dari Site Administration Menu**

1. **Login sebagai Admin**
2. **Navigate ke:**
   ```
   Site administration → Local plugins → Security Dashboard → Phishing Content Scanner
   ```
3. **Langsung masuk ke halaman scanner**

---

## 🎯 Cara Menggunakan Phishing Scanner

### **Step 1: Pilih Target Scan**

Di halaman Phishing Scanner, Anda akan melihat 3 tombol biru:

```
┌─────────────────────────────────────────────────────────┐
│  Select Content Type to Scan:                           │
│                                                          │
│  [Scan User Profiles (Bio)]  [Scan Forum Posts]         │
│  [Scan Comments]                                         │
└─────────────────────────────────────────────────────────┘
```

**Pilihan Scan:**

1. **Scan User Profiles (Bio)**
   - Scan bio/description semua user aktif
   - Maximum 1000 users per scan
   - Deteksi phishing links di profile

2. **Scan Forum Posts**
   - Scan forum posts 30 hari terakhir
   - Maximum 500 posts per scan
   - Deteksi phishing di diskusi kelas

3. **Scan Comments**
   - Scan comments 30 hari terakhir
   - Maximum 500 comments per scan
   - Deteksi phishing di assignment/activity comments

---

### **Step 2: Review Scan Results**

Setelah klik salah satu tombol, akan muncul hasil scan:

#### **Summary Box:**
```
┌─────────────────────────────────────────────────┐
│  Summary:                                        │
│  Total Scanned: 245                             │
│  Suspicious Items: 3                            │
└─────────────────────────────────────────────────┘
```

#### **Detail Table:**
```
┌──────────────────┬────────────┬──────────┬──────────────────────┐
│ User/ID          │ Risk Score │ Findings │ Details              │
├──────────────────┼────────────┼──────────┼──────────────────────┤
│ John Doe (john)  │   [7.0]    │    2     │ CRITICAL: URL        │
│                  │            │          │ Shortener detected   │
│                  │            │          │ bit.ly/xyz123        │
├──────────────────┼────────────┼──────────┼──────────────────────┤
│ Jane Smith       │   [5.0]    │    1     │ MEDIUM: Link text    │
│ (jsmith)         │            │          │ mismatch             │
└──────────────────┴────────────┴──────────┴──────────────────────┘
```

**Risk Score Color Coding:**
- 🔴 **8.0-10.0**: CRITICAL (Badge merah)
- 🟠 **6.0-7.9**: HIGH (Badge orange)
- 🟡 **4.0-5.9**: MEDIUM (Badge kuning)
- 🟢 **0.0-3.9**: LOW (Badge hijau)

---

## 🔍 Apa yang Dideteksi?

### **1. URL Shorteners**
```
❌ http://bit.ly/xyz123
❌ http://tinyurl.com/abc456
```
**Risk:** Menyembunyikan URL tujuan sebenarnya

### **2. Suspicious Domains**
```
❌ http://gooogle.com  (typosquatting)
❌ http://microsoft.com.phishing.tk
❌ http://moodle-login.ml
```
**Risk:** Domain mirip tapi palsu

### **3. Link Text Mismatch**
```html
❌ <a href="http://phishing.com">Click for Moodle Login</a>
```
**Risk:** Text bilang "Moodle" tapi link ke site lain

### **4. IP-based URLs**
```
❌ http://192.168.1.100/steal
❌ http://10.0.0.5/malware
```
**Risk:** Tidak pakai domain name (mencurigakan)

### **5. Urgency Keywords (Social Engineering)**
```
❌ "URGENT! Akun anda akan diblokir!"
❌ "Segera verifikasi atau akan dihapus"
❌ "Anda menang hadiah, klik sekarang!"
```
**Risk:** Teknik social engineering untuk panic users

### **6. Suspicious TLDs**
```
❌ .tk, .ml, .ga, .cf (free domains)
❌ .zip, .click, .link (suspicious)
```
**Risk:** TLD sering dipakai phishing

### **7. External Links**
```
✅ http://your-university.ac.id/moodle  (internal - OK)
⚠️ http://external-site.com  (external - perlu review)
```

### **8. URL Obfuscation**
```
❌ http://site.com/%2E%2E%2F%2E%2E%2F
```
**Risk:** URL encoding berlebihan untuk sembunyikan pattern

---

## 🚨 Recommended Actions

### **CRITICAL (8.0-10.0):**
```
⚠️ IMMEDIATE ACTION REQUIRED
1. Block content immediately
2. Suspend user account temporarily
3. Investigate other activity
4. Contact security team
5. Document incident
```

### **HIGH (6.0-7.9):**
```
⚡ HIGH PRIORITY
1. Review content within 24 hours
2. Remove suspicious content
3. Warn user via message
4. Monitor user activity
5. Add to watchlist
```

### **MEDIUM (4.0-5.9):**
```
⚠️ INVESTIGATE
1. Manual review required
2. Context analysis
3. Contact user for clarification
4. Consider content removal
```

### **LOW (0.0-3.9):**
```
ℹ️ MONITOR
1. Log for future reference
2. May be false positive
3. Watch for patterns
4. No immediate action needed
```

---

## 📊 Example Scenarios

### **Scenario 1: Student Profile dengan URL Shortener**

**Bio Content:**
```
Halo! Saya mahasiswa baru. 
Klik link ini untuk info beasiswa: http://bit.ly/xyz123
```

**Detection Result:**
```
Risk Score: 7.0 (HIGH)
Indicators:
- URL Shortener detected (bit.ly)
- External link (outside Moodle)
- Urgency keyword: "info"

Recommendation: HIGH RISK - Review and likely remove
```

**Action:**
1. Review profile content
2. Check bit.ly destination (jika aman: whitelist, jika berbahaya: hapus)
3. Warn student tentang policy
4. Update bio atau suspend

---

### **Scenario 2: Forum Post dengan Phishing Link**

**Post Content:**
```html
<a href="http://moodle-verify.tk/login">
  URGENT! Verifikasi akun Moodle anda sekarang atau akan diblokir!
</a>
```

**Detection Result:**
```
Risk Score: 9.0 (CRITICAL)
Indicators:
- Suspicious TLD detected (.tk)
- Domain spoofing (moodle-verify vs real Moodle)
- Social engineering keywords: URGENT, verifikasi, blokir
- Link text mismatch

Recommendation: CRITICAL - Block immediately
```

**Action:**
1. ❌ DELETE post immediately
2. 🚫 SUSPEND user account
3. 🔍 INVESTIGATE: Check all user's content
4. 📧 REPORT: Notify security team
5. 📝 DOCUMENT: Log incident dengan evidence

---

### **Scenario 3: Comment dengan Legitimate Link**

**Comment Content:**
```
Check this great tutorial: https://www.youtube.com/watch?v=abc123
```

**Detection Result:**
```
Risk Score: 1.0 (LOW)
Indicators:
- External link (outside Moodle)

Recommendation: LOW RISK - Monitor
```

**Action:**
1. ✅ No action needed (YouTube adalah legitimate)
2. ℹ️ Log untuk reference
3. 👀 Monitor jika ada complaints

---

## ⚙️ Configuration

### **Whitelist Management (Future Enhancement)**

Untuk mengurangi false positives, admin dapat whitelist:

```php
// config.php
$CFG->phishing_whitelist_domains = [
    'youtube.com',
    'google.com',
    'university.ac.id',
    'official-partner.com'
];

$CFG->phishing_whitelist_shorteners = [
    'bit.ly/institutional-*',  // Institutional bit.ly links
];
```

### **Scan Frequency**

Recommended schedule:
- **Daily:** Scan new content (last 24h)
- **Weekly:** Full user profile scan
- **Monthly:** Comprehensive audit

---

## 📈 Performance Expectations

| Operation | Items | Time | Notes |
|-----------|-------|------|-------|
| User Profile Scan | 1000 | < 2 min | Max per run |
| Forum Post Scan | 500 | < 1 min | Last 30 days |
| Comment Scan | 500 | < 1 min | Last 30 days |
| Single Content | 1 | < 200ms | API call |

---

## 🔧 Troubleshooting

### **Problem: "Service Unavailable"**

**Solution:**
1. Check proxy service: `http://localhost:8999/health`
2. Restart proxy: `docker-compose restart proxy`
3. Check logs: `proxy/logs/app.log`

### **Problem: "Too Many False Positives"**

**Solution:**
1. Review detection thresholds
2. Add legitimate domains to whitelist
3. Adjust risk scoring weights
4. Tune keyword matching

### **Problem: "Scan Too Slow"**

**Solution:**
1. Reduce batch size (1000 → 500)
2. Enable caching
3. Optimize database queries
4. Consider background jobs

---

## 📞 Support

For issues or questions:
- **Technical:** Check `SECURITY.md`
- **Configuration:** See `QUICK_START.md`
- **Testing:** Refer to `TESTING_GUIDE.md`

---

## ✅ Quick Checklist

Before using Phishing Scanner:

- [ ] Proxy service running (`docker-compose up`)
- [ ] Admin privileges enabled
- [ ] Test data available (create test user with phishing link)
- [ ] Understand action thresholds (CRITICAL/HIGH/MEDIUM/LOW)
- [ ] Action plan for incidents ready

---

**Last Updated:** January 2026  
**Version:** 1.0.0  
**Author:** MoodleSec Team
