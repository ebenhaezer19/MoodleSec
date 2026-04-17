# Script untuk sync semua debug system files ke WSL
# Run: powershell -ExecutionPolicy Bypass -File sync_to_wsl.ps1

$ErrorActionPreference = "Stop"

# Configuration
$windowsPath = "C:\Users\Admin\OneDrive\Desktop\Kuliah Guwa\TA\MoodleSec"
$wslPath = "/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec"
$wslDistro = "Ubuntu"

Write-Host "🔄 Starting sync to WSL..." -ForegroundColor Cyan
Write-Host "Windows Path: $windowsPath" -ForegroundColor Gray
Write-Host "WSL Path: $wslPath" -ForegroundColor Gray
Write-Host ""

# List of files to sync (relative paths)
$files = @(
    # Proxy Python files
    "proxy/utils/payload_debug_logger.py",
    "proxy/utils/debug_endpoints.py",
    "proxy/app.py",
    "proxy/INTEGRATION_INSTRUCTIONS.txt",
    
    # Moodle PHP files
    "moodle-plugin/debug_display.php",
    "moodle-plugin/DEBUG_INTEGRATION_GUIDE.md",
    
    # Documentation files
    "DEBUG_SYSTEM_COMPLETION_REPORT.md",
    "ARCHITECTURE_DIAGRAMS.md",
    "QUICK_ACTION_STEPS.md"
)

$successCount = 0
$failureCount = 0

foreach ($file in $files) {
    $sourceFile = Join-Path $windowsPath $file
    $destFile = $file -replace "\\", "/"
    
    try {
        if (-not (Test-Path $sourceFile)) {
            Write-Host "⚠️  File not found locally: $file" -ForegroundColor Yellow
            $failureCount++
            continue
        }
        
        # Get file info
        $fileSize = (Get-Item $sourceFile).Length
        $fileSizeKB = [math]::Round($fileSize / 1024, 2)
        
        # Copy using wsl cp command
        $wslCommand = "cp `"$sourceFile`" `"$wslPath/$destFile`""
        
        # Try direct copy first (for Windows subsystem)
        Copy-Item -Path $sourceFile -Destination "$wslPath/$($file -replace '/', '\\')" -Force -ErrorAction Stop
        
        Write-Host "✅ Synced: $file ($fileSizeKB KB)" -ForegroundColor Green
        $successCount++
    }
    catch {
        # Try WSL command if direct copy fails
        try {
            $result = wsl -d $wslDistro -- cp "$sourceFile" "$wslPath/$destFile" 2>&1
            Write-Host "✅ Synced (via WSL): $file ($fileSizeKB KB)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "❌ Failed to sync: $file - $_" -ForegroundColor Red
            $failureCount++
        }
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sync Summary:" -ForegroundColor Cyan
Write-Host "✅ Successfully synced: $successCount files" -ForegroundColor Green
Write-Host "❌ Failed: $failureCount files" -ForegroundColor $(if ($failureCount -eq 0) { "Green" } else { "Red" })
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

# Verify files in WSL
Write-Host ""
Write-Host "🔍 Verifying files in WSL..." -ForegroundColor Cyan
Write-Host ""

$verifyCommand = "ls -lah /mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/proxy/utils/ /mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/ /mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/*.md 2>/dev/null | grep -E '(debug|INTEGRATION|COMPLETION|ARCHITECTURE|QUICK)' | head -20"

try {
    $verification = wsl -d $wslDistro -- bash -c $verifyCommand
    if ($verification) {
        Write-Host $verification -ForegroundColor Cyan
    }
}
catch {
    Write-Host "⚠️  Could not verify in WSL, but files should be copied" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✨ Sync complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Open WSL terminal: wsl -d Ubuntu" -ForegroundColor Gray
Write-Host "2. Navigate to MoodleSec folder in WSL" -ForegroundColor Gray
Write-Host "3. Verify files are copied" -ForegroundColor Gray
Write-Host "4. Start integration following QUICK_ACTION_STEPS.md" -ForegroundColor Gray
