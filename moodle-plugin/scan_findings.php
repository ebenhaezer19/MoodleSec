<?php
/**
 * Scan Findings Detail Page
 * Shows per-finding details: PoC, CVSS, recommendation, config suggestion, verify fix (L2-L7)
 *
 * @package    local_security_dashboard
 * @copyright  2024 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once('lib.php');

require_login();
$context = context_system::instance();
require_capability('moodle/site:config', $context);

$scan_id = required_param('scan_id', PARAM_TEXT);
$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/local/security_dashboard/scan_findings.php', ['scan_id' => $scan_id]));
$PAGE->set_title('Scan Findings — ' . $scan_id);
$PAGE->set_heading('Security Findings Detail');

$proxy_url = rtrim(get_config('local_security_dashboard', 'proxy_url') ?: 'http://localhost:8998', '/');
$plugin_url = (new moodle_url('/local/security_dashboard/'))->out(false);

// Fetch findings from proxy
$findings = [];
$scan_meta = [];
try {
    $curl = new curl();
    $response = $curl->get($proxy_url . '/api/scan/' . urlencode($scan_id));
    $data = json_decode($response, true);
    if ($data && isset($data['findings'])) {
        $findings = $data['findings'];
        $scan_meta = $data;
    }
} catch (Exception $e) {
    // If proxy not available, findings will be empty
}

echo $OUTPUT->header();

// Severity badge helper
function severity_badge(string $sev): string {
    $map = [
        'critical' => 'danger',
        'high'     => 'warning',
        'medium'   => 'info',
        'low'      => 'secondary',
        'info'     => 'light',
    ];
    $lower = strtolower($sev);
    $cls = $map[$lower] ?? 'secondary';
    return "<span class='badge badge-{$cls}'>" . htmlspecialchars(ucfirst($sev)) . "</span>";
}
?>

<style>
.finding-card { border-left: 5px solid #dc3545; margin-bottom: 20px; }
.finding-card.high { border-left-color: #fd7e14; }
.finding-card.medium { border-left-color: #0dcaf0; }
.finding-card.low { border-left-color: #6c757d; }
.poc-block { background: #1e1e1e; color: #d4d4d4; font-family: monospace;
             font-size: 12px; padding: 12px; border-radius: 6px; white-space: pre-wrap; }
.config-block { background: #f4f3ff; border: 1px solid #8b5cf6; border-radius: 6px;
                padding: 12px; font-family: monospace; font-size: 12px; white-space: pre-wrap; }
.step-list li { margin-bottom: 6px; }
.cvss-badge { font-size: 1.1em; font-weight: bold; padding: 6px 14px; border-radius: 20px; }
.verify-result { display: none; margin-top: 10px; }
.section-label { font-size: 0.78em; text-transform: uppercase; letter-spacing: 1px;
                 color: #6c757d; font-weight: 700; margin-bottom: 4px; }
</style>

<!-- Header -->
<div class="d-flex justify-content-between align-items-center mb-4">
    <div>
        <h4>📋 Findings for Scan <code><?php echo htmlspecialchars($scan_id); ?></code></h4>
        <small class="text-muted"><?php echo count($findings); ?> finding(s) after ML filtering</small>
    </div>
    <div>
        <a href="reports.php" class="btn btn-sm btn-secondary">⬅ Back to Reports</a>
        <a href="download_report.php?scan_id=<?php echo urlencode($scan_id); ?>&type=compliance&framework=PCI-DSS"
           class="btn btn-sm btn-primary" target="_blank">📄 Download PDF</a>
    </div>
</div>

<?php if (empty($findings)): ?>
<div class="alert alert-warning">
    <strong>No findings available.</strong> Either the proxy is offline or this scan has no findings.
    <br><small>Proxy URL: <?php echo htmlspecialchars($proxy_url); ?></small>
</div>
<?php else: ?>

<?php foreach ($findings as $idx => $finding):
    $sev = strtolower($finding['severity'] ?? 'info');
    $cvss = $finding['cvss_score'] ?? 0;
    $category = $finding['category'] ?? 'Unknown';
    $url = $finding['url'] ?? 'N/A';
    $parameter = $finding['parameter'] ?? ($finding['poc']['request']['parameter'] ?? 'N/A');
    $payload = $finding['poc']['request']['payload'] ?? 'N/A';
    $evidence = $finding['evidence'] ?? 'N/A';
    $recommendation = $finding['recommendation'] ?? '';
    $rec_source = $finding['recommendation_source'] ?? 'static';
    $steps = $finding['remediation_steps'] ?? [];
    $code_fix = $finding['code_fix'] ?? '';
    $config_fix = $finding['config_fix'] ?? [];
    $poc = $finding['poc'] ?? [];
    $poc_steps = $poc['steps'] ?? [];
    $verify = $finding['verify_fix'] ?? ['can_auto_verify' => false];
    $references = $finding['references'] ?? [];
    $finding_id = $finding['id'] ?? ($idx + 1);
?>

<div class="card finding-card <?php echo $sev; ?>">
    <div class="card-header d-flex justify-content-between align-items-center">
        <div>
            <strong>#<?php echo $idx + 1; ?> — <?php echo htmlspecialchars($category); ?></strong>
            <?php echo severity_badge($sev); ?>
            <?php if ($finding['cwe'] ?? ''): ?>
                <span class="badge badge-dark ml-1"><?php echo htmlspecialchars($finding['cwe']); ?></span>
            <?php endif; ?>
            <?php if ($finding['owasp'] ?? ''): ?>
                <span class="badge badge-outline-secondary ml-1" style="border:1px solid #6c757d; color:#6c757d"><?php echo htmlspecialchars($finding['owasp']); ?></span>
            <?php endif; ?>
        </div>
        <div class="text-right">
            <?php if ($cvss > 0): ?>
                <?php
                $cvss_cls = $cvss >= 9 ? 'danger' : ($cvss >= 7 ? 'warning' : ($cvss >= 4 ? 'info' : 'secondary'));
                ?>
                <span class="cvss-badge badge badge-<?php echo $cvss_cls; ?>">
                    CVSS <?php echo number_format($cvss, 1); ?>
                </span>
            <?php endif; ?>
        </div>
    </div>
    <div class="card-body">

        <!-- URL + Parameter -->
        <div class="row mb-3">
            <div class="col-md-8">
                <div class="section-label">🔗 Vulnerable URL</div>
                <code style="word-break:break-all;"><?php echo htmlspecialchars($url); ?></code>
            </div>
            <div class="col-md-4">
                <div class="section-label">📌 Parameter</div>
                <code><?php echo htmlspecialchars($parameter); ?></code>
                <?php if ($payload !== 'N/A' && $payload !== 'Pattern detected in response'): ?>
                    <br><div class="section-label mt-1">💉 Payload Used</div>
                    <code class="text-danger"><?php echo htmlspecialchars($payload); ?></code>
                <?php endif; ?>
            </div>
        </div>

        <!-- Evidence -->
        <div class="mb-3">
            <div class="section-label">🔍 Evidence</div>
            <div class="poc-block"><?php echo htmlspecialchars(substr($evidence, 0, 400)); ?></div>
        </div>

        <!-- PoC Steps -->
        <?php if (!empty($poc_steps)): ?>
        <div class="mb-3">
            <div class="section-label">🧪 Proof of Concept — Reproduction Steps</div>
            <ol class="step-list">
                <?php foreach ($poc_steps as $step): ?>
                    <li><?php echo htmlspecialchars($step); ?></li>
                <?php endforeach; ?>
            </ol>
        </div>
        <?php endif; ?>

        <!-- Recommendation -->
        <div class="mb-3">
            <div class="section-label">
                💡 Recommendation
                <?php if ($rec_source === 'gpt'): ?>
                    <span class="badge badge-success ml-1">🤖 AI-Powered</span>
                <?php else: ?>
                    <span class="badge badge-secondary ml-1">📋 Template</span>
                <?php endif; ?>
            </div>
            <div class="alert alert-light border-left border-warning p-2 mb-2" style="border-left: 4px solid #ffc107 !important;">
                <?php echo nl2br(htmlspecialchars($recommendation)); ?>
            </div>
            <?php if (!empty($steps)): ?>
            <ul class="step-list">
                <?php foreach ($steps as $step): ?>
                    <li><?php echo htmlspecialchars($step); ?></li>
                <?php endforeach; ?>
            </ul>
            <?php endif; ?>
        </div>

        <!-- Code Fix -->
        <?php if ($code_fix): ?>
        <div class="mb-3">
            <div class="section-label">🔧 Code Fix</div>
            <div class="poc-block"><?php echo htmlspecialchars($code_fix); ?></div>
        </div>
        <?php endif; ?>

        <!-- L6: Config Suggestion -->
        <?php if (!empty($config_fix)): ?>
        <div class="mb-3">
            <div class="section-label">⚙️ Config Fix (L6 — Moodle/Server Configuration)</div>
            <div class="config-block">
<?php
foreach ($config_fix as $platform => $cfg) {
    if ($platform === 'description') continue;
    echo "# " . strtoupper($platform) . "\n" . htmlspecialchars($cfg) . "\n\n";
}
?>
            </div>
            <?php if ($config_fix['description'] ?? ''): ?>
                <small class="text-muted">ℹ️ <?php echo htmlspecialchars($config_fix['description']); ?></small>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- References -->
        <?php if (!empty($references)): ?>
        <div class="mb-3">
            <div class="section-label">📚 References</div>
            <ul class="list-unstyled mb-0">
                <?php foreach ($references as $ref): ?>
                    <li><small>
                        <?php if (str_starts_with($ref, 'http')): ?>
                            <a href="<?php echo htmlspecialchars($ref); ?>" target="_blank">🔗 <?php echo htmlspecialchars($ref); ?></a>
                        <?php else: ?>
                            📄 <?php echo htmlspecialchars($ref); ?>
                        <?php endif; ?>
                    </small></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>

        <!-- L7: Verify Fix Button -->
        <div class="mt-3 pt-3 border-top">
            <div class="section-label">🔍 L7 — Verify Fix</div>
            <?php if ($verify['can_auto_verify'] ?? false): ?>
                <p class="text-muted small mb-2">
                    Setelah mengimplementasikan fix, klik tombol di bawah untuk verifikasi otomatis
                    apakah vulnerability sudah berhasil diperbaiki.
                </p>
                <button class="btn btn-sm btn-outline-primary"
                        id="verify-btn-<?php echo $finding_id; ?>"
                        onclick="verifyFix('<?php echo htmlspecialchars($finding_id); ?>', '<?php echo htmlspecialchars($scan_id); ?>', this)">
                    🔍 Verify Fix
                </button>
            <?php else: ?>
                <span class="text-muted small">
                    ⚠️ <?php echo htmlspecialchars($verify['manual_verify_note'] ?? 'Verifikasi manual diperlukan'); ?>
                </span>
            <?php endif; ?>

            <div class="verify-result alert" id="verify-result-<?php echo $finding_id; ?>"></div>
        </div>

    </div><!-- /.card-body -->
</div><!-- /.card -->

<?php endforeach; ?>
<?php endif; ?>

<script>
// PHP-side proxy URL (avoids CORS from browser directly to port 8998)
const proxyApiUrl = '<?php echo rtrim((new moodle_url("/local/security_dashboard/proxy_api.php"))->out(false), "/"); ?>';

async function verifyFix(findingId, scanId, btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Verifying...';

    const resultDiv = document.getElementById('verify-result-' + findingId);
    resultDiv.style.display = 'none';

    try {
        const resp = await fetch(
            `${proxyApiUrl}?action=verify-fix&finding_id=${encodeURIComponent(findingId)}&scan_id=${encodeURIComponent(scanId)}&sesskey=<?php echo sesskey(); ?>`,
            { method: 'POST' }
        );
        const data = await resp.json();

        resultDiv.style.display = 'block';
        if (data.status === 'verified_fixed') {
            resultDiv.className = 'verify-result alert alert-success';
            resultDiv.innerHTML = `<strong>✅ Fix Verified!</strong><br>${data.message}<br>
                <small class="text-muted">Verified at: ${data.verified_at}</small>`;
            btn.textContent = '✅ Fixed';
            btn.className = 'btn btn-sm btn-success';
        } else if (data.status === 'still_vulnerable') {
            resultDiv.className = 'verify-result alert alert-danger';
            resultDiv.innerHTML = `<strong>⚠️ Still Vulnerable</strong><br>${data.message}<br>
                <small class="text-muted">Evidence: ${data.response_snippet || 'N/A'}</small>`;
            btn.textContent = '🔍 Verify Fix';
            btn.disabled = false;
        } else if (data.status === 'error') {
            resultDiv.className = 'verify-result alert alert-warning';
            resultDiv.innerHTML = `<strong>⚠️ Error</strong><br>${data.message}`;
            btn.textContent = '🔍 Verify Fix';
            btn.disabled = false;
        } else {
            resultDiv.className = 'verify-result alert alert-warning';
            resultDiv.innerHTML = data.message || 'Verification inconclusive.';
            btn.textContent = '🔍 Verify Fix';
            btn.disabled = false;
        }
    } catch (e) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'verify-result alert alert-danger';
        resultDiv.textContent = 'Connection error: ' + e.message;
        btn.textContent = '🔍 Verify Fix';
        btn.disabled = false;
    }
}
</script>

<?php echo $OUTPUT->footer(); ?>
