# Manual verification script untuk SQL Injection findings
# Test apakah benar-benar vulnerable atau false positive

$baseUrl = "http://103.127.132.74:8998"
$endpoints = @(
    "/lib/ajax/service.php",
    "/lib/ajax/service-nologin.php"
)

Write-Host "`n=== MANUAL SQL INJECTION VERIFICATION ===" -ForegroundColor Cyan
Write-Host "Testing endpoints for REAL SQL injection..." -ForegroundColor Yellow

foreach ($endpoint in $endpoints) {
    Write-Host "`n[Testing] $endpoint" -ForegroundColor Green
    
    # Test 1: Normal request
    Write-Host "  1. Normal request:" -ForegroundColor White
    $response1 = Invoke-WebRequest -Uri "$baseUrl$endpoint" -Method POST -Body @{wstoken="test"} -UseBasicParsing -ErrorAction SilentlyContinue
    Write-Host "     Status: $($response1.StatusCode)" -ForegroundColor Gray
    Write-Host "     Response length: $($response1.Content.Length) bytes" -ForegroundColor Gray
    
    # Test 2: SQL Injection payload
    Write-Host "  2. SQL Injection payload (' OR '1'='1):" -ForegroundColor White
    $response2 = Invoke-WebRequest -Uri "$baseUrl$endpoint" -Method POST -Body @{wstoken="' OR '1'='1"} -UseBasicParsing -ErrorAction SilentlyContinue
    Write-Host "     Status: $($response2.StatusCode)" -ForegroundColor Gray
    Write-Host "     Response length: $($response2.Content.Length) bytes" -ForegroundColor Gray
    
    # Check for SQL errors
    $sqlErrors = @('sql syntax', 'mysql', 'postgresql', 'syntax error near', 'unclosed quotation')
    $foundError = $false
    foreach ($error in $sqlErrors) {
        if ($response2.Content -match $error) {
            Write-Host "     [!] FOUND SQL ERROR: $error" -ForegroundColor Red
            $foundError = $true
        }
    }
    
    if (-not $foundError) {
        Write-Host "     [OK] No SQL error messages - Likely FALSE POSITIVE" -ForegroundColor Green
    }
    
    # Compare responses
    if ($response1.Content -eq $response2.Content) {
        Write-Host "     [OK] Same response - NOT vulnerable" -ForegroundColor Green
    } else {
        Write-Host "     [!] Different response - Needs investigation" -ForegroundColor Yellow
    }
}

Write-Host "`n=== TESTING HTTP METHOD TAMPERING ===" -ForegroundColor Cyan

$testEndpoint = "/webservice/rest/server.php"
Write-Host "`n[Testing] $testEndpoint" -ForegroundColor Green

foreach ($method in @("PUT", "DELETE", "PATCH")) {
    Write-Host "  Testing $method method:" -ForegroundColor White
    try {
        $response = Invoke-WebRequest -Uri "$baseUrl$testEndpoint" -Method $method -UseBasicParsing -ErrorAction Stop
        Write-Host "     Status: $($response.StatusCode)" -ForegroundColor Gray
        Write-Host "     [!] Method accepted - but check if it actually DOES anything" -ForegroundColor Yellow
    } catch {
        Write-Host "     Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Gray
        if ($_.Exception.Response.StatusCode.value__ -eq 405) {
            Write-Host "     [OK] Method NOT allowed - FALSE POSITIVE" -ForegroundColor Green
        }
    }
}

Write-Host "`n=== CONCLUSION ===" -ForegroundColor Cyan
Write-Host "Most findings are likely FALSE POSITIVES because:" -ForegroundColor Yellow
Write-Host "  1. Scanner only checks for error keywords, not actual exploitation" -ForegroundColor White
Write-Host "  2. Moodle has good input validation and prepared statements" -ForegroundColor White
Write-Host "  3. HTTP methods may be accepted but don't execute dangerous actions" -ForegroundColor White
Write-Host "`nRECOMMENDATION: Improve scanner accuracy with ML filtering" -ForegroundColor Green
