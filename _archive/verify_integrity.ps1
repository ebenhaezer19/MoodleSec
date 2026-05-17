Write-Host "=== RUNTIME INTEGRITY VERIFICATION ==="
Write-Host ""

$allGood = $true

function Check($label, $path) {
    $exists = Test-Path $path
    $status = if($exists) { "OK" } else { "MISSING!" }
    Write-Host "  [$status] $label"
    if(-not $exists) { $script:allGood = $false }
}

Write-Host "--- Core Files ---"
Check "app.py" "proxy\app.py"
Check "config.py" "proxy\config.py"
Check "alert_queue.py" "proxy\utils\alert_queue.py"
Check "trace_logger.py" "proxy\utils\trace_logger.py"
Check "logger.py" "proxy\utils\logger.py"
Check "security_events.py" "proxy\utils\security_events.py"
Check "slack_notifier.py" "proxy\utils\slack_notifier.py"

Write-Host "`n--- ML Pipeline ---"
Check "ml_manager.py" "proxy\ml\ml_manager.py"
Check "pipeline_orchestrator.py" "proxy\ml\pipeline_orchestrator.py"
Check "attack_classifier.py" "proxy\ml\attack_classifier.py"
Check "anomaly_detector.py" "proxy\ml\anomaly_detector.py"
Check "false_positive_reducer.py" "proxy\ml\false_positive_reducer.py"
Check "decision_engine.py" "proxy\ml\decision_engine.py"
Check "runtime_integrity.py" "proxy\ml\runtime_integrity.py"

Write-Host "`n--- ML Models ---"
Check "attack_classifier.pkl" "proxy\ml\models\attack_classifier.pkl"
Check "anomaly_detector.pkl" "proxy\ml\models\anomaly_detector.pkl"
Check "fp_reducer.pkl" "proxy\ml\models\fp_reducer.pkl"
Check "severity_predictor.pkl" "proxy\ml\models\severity_predictor.pkl"
Check "feature_importance.json" "proxy\ml\models\feature_importance.json"

Write-Host "`n--- SOC Dashboard ---"
Check "index.html" "proxy\soc-dashboard\index.html"
Check "app.js" "proxy\soc-dashboard\js\app.js"
Check "api.js" "proxy\soc-dashboard\js\api.js"
Check "base.css" "proxy\soc-dashboard\css\base.css"

Write-Host "`n--- Integrations ---"
Check "ml_pipeline_integration.py" "proxy\integrations\ml_pipeline_integration.py"
Check "integration_manager.py" "proxy\integrations\integration_manager.py"

Write-Host "`n--- Scanners/Routers ---"
Check "scanner_engine.py" "proxy\scanners\scanner_engine.py"
Check "payload_router.py" "proxy\routers\payload_router.py"
Check "scanner_router.py" "proxy\routers\scanner_router.py"

Write-Host "`n--- Database ---"
Check "scan_history.py" "proxy\database\scan_history.py"
Check "payload_repository.py" "proxy\database\payload_repository.py"
Check "scheduler_db.py" "proxy\database\scheduler_db.py"

Write-Host "`n--- Other Runtime ---"
Check "pdf_generator.py" "proxy\reporting\pdf_generator.py"
Check "risk_scorer.py" "proxy\risk\risk_scorer.py"
Check "web_crawler.py" "proxy\crawler\web_crawler.py"
Check "scan_scheduler.py" "proxy\scheduler\scan_scheduler.py"

Write-Host "`n--- Archive Structure ---"
Get-ChildItem "_archive" -Recurse -File | ForEach-Object {
    Write-Host ("  " + $_.FullName.Replace((Get-Location).Path + "\", ""))
}

Write-Host "`n==========================="
if($allGood) {
    Write-Host "ALL CHECKS PASSED - Runtime intact!"
} else {
    Write-Host "WARNING: Some files missing!"
}
