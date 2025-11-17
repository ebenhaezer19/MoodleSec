# PowerShell Testing Script for MoodleSec Backend
# Usage: .\test_powershell.ps1

Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "MoodleSec Backend Testing (PowerShell)" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

$passed = 0
$failed = 0

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Body = $null,
        [string]$ExpectedContent = ""
    )
    
    Write-Host "Testing: $Name" -ForegroundColor Yellow
    
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            ContentType = "application/json"
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json)
        }
        
        $response = Invoke-RestMethod @params
        $responseText = $response | ConvertTo-Json
        
        if ($ExpectedContent -eq "" -or $responseText -match $ExpectedContent) {
            Write-Host "✅ PASSED: $Name" -ForegroundColor Green
            $script:passed++
            return $response
        } else {
            Write-Host "❌ FAILED: $Name - Expected content not found" -ForegroundColor Red
            $script:failed++
            return $null
        }
    }
    catch {
        Write-Host "❌ FAILED: $Name - $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
        return $null
    }
}

# ============================================
# 1. Service Health Checks
# ============================================
Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "1. Service Health Checks" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

Test-Endpoint -Name "CVSS Engine Health" -Url "http://localhost:8001/health" -ExpectedContent "ok"
Test-Endpoint -Name "Proxy Service Health" -Url "http://localhost:8999/health" -ExpectedContent "ok"

# ============================================
# 2. CVSS Engine Tests
# ============================================
Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "2. CVSS Engine Tests" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

# Test 2.1: Calculate Critical CVSS Score
$cvssBody = @{
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
$result = Test-Endpoint -Name "Calculate Critical CVSS (9.8)" -Url "http://localhost:8001/score" -Method "POST" -Body $cvssBody -ExpectedContent "9.8"
if ($result) {
    Write-Host "  Score: $($result.score), Severity: $($result.severity)" -ForegroundColor Cyan
}

# Test 2.2: Calculate Medium CVSS Score
$cvssBody = @{
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
}
$result = Test-Endpoint -Name "Calculate Medium CVSS (6.1)" -Url "http://localhost:8001/score" -Method "POST" -Body $cvssBody -ExpectedContent "6.1"
if ($result) {
    Write-Host "  Score: $($result.score), Severity: $($result.severity)" -ForegroundColor Cyan
}

# Test 2.3: Invalid CVSS Vector
$cvssBody = @{
    vector = "INVALID"
}
Write-Host "Testing: Handle Invalid CVSS Vector" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8001/score" -Method POST -Body ($cvssBody | ConvertTo-Json) -ContentType "application/json"
    Write-Host "❌ FAILED: Should have rejected invalid vector" -ForegroundColor Red
    $script:failed++
}
catch {
    if ($_.Exception.Response.StatusCode -eq 400) {
        Write-Host "✅ PASSED: Invalid CVSS vector rejected" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "❌ FAILED: Unexpected error" -ForegroundColor Red
        $script:failed++
    }
}

# ============================================
# 3. Proxy Service Tests
# ============================================
Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "3. Proxy Service Tests" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

# Test 3.1: Get Logs
Test-Endpoint -Name "Get Proxy Logs" -Url "http://localhost:8999/logs" -ExpectedContent "count"

# Test 3.2: Trigger Scan - Login Page
$scanBody = @{
    path = "/login/index.php"
    method = "POST"
}
$result = Test-Endpoint -Name "Trigger Scan - Login Page" -Url "http://localhost:8999/scan-trigger" -Method "POST" -Body $scanBody -ExpectedContent "scan_id"
if ($result) {
    Write-Host "  Scan ID: $($result.scan_id)" -ForegroundColor Cyan
    Write-Host "  Findings: $($result.findings.Count)" -ForegroundColor Cyan
    Write-Host "  Summary: Critical=$($result.summary.critical), High=$($result.summary.high), Medium=$($result.summary.medium)" -ForegroundColor Cyan
}

# Test 3.3: Trigger Scan - Admin Page
$scanBody = @{
    path = "/admin/settings.php"
    method = "GET"
}
$result = Test-Endpoint -Name "Trigger Scan - Admin Page" -Url "http://localhost:8999/scan-trigger" -Method "POST" -Body $scanBody -ExpectedContent "High"
if ($result) {
    Write-Host "  Scan ID: $($result.scan_id)" -ForegroundColor Cyan
    Write-Host "  Findings: $($result.findings.Count)" -ForegroundColor Cyan
    Write-Host "  Summary: Critical=$($result.summary.critical), High=$($result.summary.high), Medium=$($result.summary.medium)" -ForegroundColor Cyan
}

# Test 3.4: Get Logs After Scans
Start-Sleep -Seconds 1
Test-Endpoint -Name "Get Logs After Scans" -Url "http://localhost:8999/logs?limit=5" -ExpectedContent "dast_scan"

# ============================================
# 4. Integration Test
# ============================================
Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "4. Integration Test" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

Write-Host "Testing: Complete Workflow" -ForegroundColor Yellow

# Trigger scan
$scanBody = @{
    path = "/test/page.php"
    method = "GET"
}
$scanResult = Invoke-RestMethod -Uri "http://localhost:8999/scan-trigger" -Method POST -Body ($scanBody | ConvertTo-Json) -ContentType "application/json"

if ($scanResult.scan_id) {
    Write-Host "✅ PASSED: Scan triggered (ID: $($scanResult.scan_id))" -ForegroundColor Green
    $script:passed++
    
    # Calculate CVSS for a finding
    $cvssBody = @{
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    }
    $cvssResult = Invoke-RestMethod -Uri "http://localhost:8001/score" -Method POST -Body ($cvssBody | ConvertTo-Json) -ContentType "application/json"
    
    if ($cvssResult.score) {
        Write-Host "✅ PASSED: CVSS calculated ($($cvssResult.score) - $($cvssResult.severity))" -ForegroundColor Green
        $script:passed++
    }
} else {
    Write-Host "❌ FAILED: Scan trigger failed" -ForegroundColor Red
    $script:failed++
}

# ============================================
# 5. Error Handling Tests
# ============================================
Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "5. Error Handling Tests" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

# Test 5.1: Missing Required Field
Write-Host "Testing: Missing Required Field" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8999/scan-trigger" -Method POST -Body "{}" -ContentType "application/json"
    Write-Host "❌ FAILED: Should have rejected empty body" -ForegroundColor Red
    $script:failed++
}
catch {
    if ($_.Exception.Response.StatusCode -eq 422 -or $_.Exception.Response.StatusCode -eq 400) {
        Write-Host "✅ PASSED: Missing field rejected" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "❌ FAILED: Unexpected error" -ForegroundColor Red
        $script:failed++
    }
}

# ============================================
# Summary
# ============================================
Write-Host "`n============================================" -ForegroundColor Blue
Write-Host "Test Summary" -ForegroundColor Blue
Write-Host "============================================`n" -ForegroundColor Blue

$total = $passed + $failed
$passRate = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 2) } else { 0 }

Write-Host "Total Tests: $total"
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host "Pass Rate: $passRate%"

if ($failed -eq 0) {
    Write-Host "`n🎉 All tests passed! Backend is ready.`n" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Some tests failed. Please review the output above.`n" -ForegroundColor Yellow
}
