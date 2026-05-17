# PowerShell Script untuk verifikasi semua debug system files
# Run: powershell -ExecutionPolicy Bypass -File verify_files.ps1

$ErrorActionPreference = "SilentlyContinue"

Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     DEBUG SYSTEM FILES VERIFICATION                   ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$moodlePath = "C:\Users\Admin\OneDrive\Desktop\Kuliah Guwa\TA\MoodleSec"

# Backend Python Files
Write-Host "🐍 BACKEND PYTHON FILES (proxy/utils/)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
$backendFiles = @(
    "proxy/utils/payload_debug_logger.py",
    "proxy/utils/debug_endpoints.py",
    "proxy/app.py"
)

$backendCount = 0
foreach ($file in $backendFiles) {
    $fullPath = Join-Path $moodlePath $file
    if (Test-Path $fullPath) {
        $size = (Get-Item $fullPath).Length / 1KB
        Write-Host "✅ $(Split-Path -Leaf $file)" -ForegroundColor Green -NoNewline
        Write-Host " ($([math]::Round($size, 1)) KB)" -ForegroundColor Gray
        $backendCount++
    } else {
        Write-Host "❌ $(Split-Path -Leaf $file) - NOT FOUND" -ForegroundColor Red
    }
}

# Frontend PHP Files
Write-Host ""
Write-Host "🎨 FRONTEND PHP FILES (moodle-plugin/)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
$frontendFiles = @(
    "moodle-plugin/debug_display.php",
    "moodle-plugin/lib.php",
    "moodle-plugin/payload_management.php",
    "moodle-plugin/settings.php",
    "moodle-plugin/version.php"
)

$frontendCount = 0
foreach ($file in $frontendFiles) {
    $fullPath = Join-Path $moodlePath $file
    if (Test-Path $fullPath) {
        $size = (Get-Item $fullPath).Length / 1KB
        Write-Host "✅ $(Split-Path -Leaf $file)" -ForegroundColor Green -NoNewline
        Write-Host " ($([math]::Round($size, 1)) KB)" -ForegroundColor Gray
        $frontendCount++
    } else {
        Write-Host "❌ $(Split-Path -Leaf $file) - NOT FOUND" -ForegroundColor Red
    }
}

# Documentation Files
Write-Host ""
Write-Host "📖 DOCUMENTATION FILES" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
$docFiles = @(
    "DEBUG_SYSTEM_COMPLETION_REPORT.md",
    "ARCHITECTURE_DIAGRAMS.md",
    "QUICK_ACTION_STEPS.md",
    "proxy/INTEGRATION_INSTRUCTIONS.txt",
    "moodle-plugin/DEBUG_INTEGRATION_GUIDE.md"
)

$docCount = 0
foreach ($file in $docFiles) {
    $fullPath = Join-Path $moodlePath $file
    if (Test-Path $fullPath) {
        $size = (Get-Item $fullPath).Length / 1KB
        Write-Host "✅ $(Split-Path -Leaf $file)" -ForegroundColor Green -NoNewline
        Write-Host " ($([math]::Round($size, 1)) KB)" -ForegroundColor Gray
        $docCount++
    } else {
        Write-Host "❌ $(Split-Path -Leaf $file) - NOT FOUND" -ForegroundColor Red
    }
}

# Summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    SUMMARY                             ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend Python Files:  $backendCount/$($backendFiles.Count)" -ForegroundColor Cyan
Write-Host "Frontend PHP Files:    $frontendCount/$($frontendFiles.Count)" -ForegroundColor Cyan
Write-Host "Documentation Files:   $docCount/$($docFiles.Count)" -ForegroundColor Cyan
Write-Host ""

$allCount = $backendCount + $frontendCount + $docCount
$totalCount = $backendFiles.Count + $frontendFiles.Count + $docFiles.Count

if ($allCount -eq $totalCount) {
    Write-Host "✅ ALL FILES PRESENT - Ready to integrate!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. In WSL, run: bash copy_to_moodle.sh" -ForegroundColor Gray
    Write-Host "2. Verify files copied to:" -ForegroundColor Gray
    Write-Host "   /var/www/html/moodle/public/local/security_dashboard" -ForegroundColor Gray
    Write-Host "3. Restart Moodle services" -ForegroundColor Gray
} else {
    Write-Host "⚠️  SOME FILES MISSING ($allCount/$totalCount found)" -ForegroundColor Red
}

Write-Host ""
