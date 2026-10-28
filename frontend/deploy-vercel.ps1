# SPPIO Command Console - Vercel Deployment Script
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   SPPIO Command Console - Vercel Deploy   " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Set-Location -Path $PSScriptRoot

Write-Host "`n[1/4] Ensuring Vercel CLI is available..." -ForegroundColor Yellow
$vercelInstalled = Get-Command vercel -ErrorAction SilentlyContinue

if (-not $vercelInstalled) {
    Write-Host "Installing Vercel CLI globally (bypasses npm cache locks)..." -ForegroundColor Gray
    npm install -g vercel --prefer-online
}

Write-Host "`n[2/4] Building frontend bundle..." -ForegroundColor Yellow
npm run build

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Frontend build failed." -ForegroundColor Red
    exit 1
}

Write-Host "`n[3/4] Authenticating with Vercel..." -ForegroundColor Yellow
Write-Host "Please authorize in the browser window if prompted.`n" -ForegroundColor Gray
vercel login

Write-Host "`n[4/4] Deploying to Vercel Production..." -ForegroundColor Yellow
vercel --prod

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "   Deployment Complete! Check the URL above." -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
