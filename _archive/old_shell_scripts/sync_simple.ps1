# Simple script untuk sync debug files ke WSL

$ErrorActionPreference = "Stop"

$windowsPath = "C:\Users\Admin\OneDrive\Desktop\Kuliah Guwa\TA\MoodleSec"
$files = @(
    "proxy/utils/payload_debug_logger.py",
    "proxy/utils/debug_endpoints.py",
    "proxy/app.py",
    "proxy/INTEGRATION_INSTRUCTIONS.txt",
    "moodle-plugin/debug_display.php",
    "moodle-plugin/DEBUG_INTEGRATION_GUIDE.md",
    "DEBUG_SYSTEM_COMPLETION_REPORT.md",
    "ARCHITECTURE_DIAGRAMS.md",
    "QUICK_ACTION_STEPS.md"
)

Write-Host "Syncing debug system files to WSL..." -ForegroundColor Cyan
Write-Host ""

$count = 0
foreach ($file in $files) {
    $source = Join-Path $windowsPath $file
    if (Test-Path $source) {
        Write-Host "✅ $file" -ForegroundColor Green
        $count++
    } else {
        Write-Host "⚠️  Missing: $file" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Total: $count files ready" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files are on Windows at: $windowsPath" -ForegroundColor Gray
Write-Host "WSL can access via:      /mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec" -ForegroundColor Gray
