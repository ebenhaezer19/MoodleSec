# Phase 2A: Debug/Check scripts from proxy/
$phase2a = @(
    'check_finding_23.py','check_findings.py','check_all_findings.py',
    'check_latest_scan.py','check_model.py','check_processed_files.py',
    'check_scans.py','check_schema.py','check_sklearn_version.py',
    'debug_filter.py','debug_overlap.py','debug_severity.py',
    'debug_zap_connection.py','debug_pipeline.py',
    'inspect_model.py','inspect_persistence.py','tmp_threshold_sweep.py'
)

Write-Host "=== Phase 2A: Debug Scripts ==="
$count2a = 0
foreach($f in $phase2a) {
    $src = Join-Path "proxy" $f
    $dst = Join-Path "_archive\debug_scripts" $f
    if(Test-Path $src) {
        Move-Item -Path $src -Destination $dst -Force
        Write-Host "  MOVED: proxy/$f"
        $count2a++
    } else {
        Write-Host "  SKIP: proxy/$f (not found)"
    }
}
Write-Host "Phase 2A: $count2a files moved`n"

# Phase 2B: Analysis scripts from proxy/
$phase2b = @(
    'analyze_needs_review.py','analyze_new_data.py',
    'analyze_real_vs_synthetic.py','analyze_scan_targets.py',
    'analyze_training.py','OPSI1_EXPLAINED.py',
    'explain_opsi1_check_zap.py','feature_shortcut_analysis.py',
    'data_provenance_audit.py','show_cve_priorities.py'
)

# ml/analyze.py needs special handling
$phase2b_ml = @('ml\analyze.py')

Write-Host "=== Phase 2B: Analysis Scripts ==="
$count2b = 0
foreach($f in $phase2b) {
    $src = Join-Path "proxy" $f
    $dst = Join-Path "_archive\analysis_scripts" $f
    if(Test-Path $src) {
        Move-Item -Path $src -Destination $dst -Force
        Write-Host "  MOVED: proxy/$f"
        $count2b++
    } else {
        Write-Host "  SKIP: proxy/$f (not found)"
    }
}
# Handle ml/analyze.py
$src = "proxy\ml\analyze.py"
$dst = "_archive\analysis_scripts\ml_analyze.py"
if(Test-Path $src) {
    Move-Item -Path $src -Destination $dst -Force
    Write-Host "  MOVED: proxy/ml/analyze.py -> ml_analyze.py"
    $count2b++
} else {
    Write-Host "  SKIP: proxy/ml/analyze.py (not found)"
}
Write-Host "Phase 2B: $count2b files moved`n"

# Phase 2D: Old shell/PowerShell scripts from root
$phase2d = @(
    'sync_to_wsl.ps1','sync_simple.ps1','test_powershell.ps1',
    'verify_files.ps1','verify_sqli.ps1','verify_xss_findings.sh',
    'fix_get_logs.sh','fix_permissions.sh','deploy_lib_fix.sh',
    'deploy_phishing_detection.sh','setup_debug_wsl.sh','check_zap_scans.sh'
)

Write-Host "=== Phase 2D: Old Shell Scripts ==="
$count2d = 0
foreach($f in $phase2d) {
    if(Test-Path $f) {
        Move-Item -Path $f -Destination (Join-Path "_archive\old_shell_scripts" $f) -Force
        Write-Host "  MOVED: $f"
        $count2d++
    } else {
        Write-Host "  SKIP: $f (not found)"
    }
}
Write-Host "Phase 2D: $count2d files moved`n"

$total = $count2a + $count2b + $count2d
Write-Host "=== TOTAL: $total files moved ==="
