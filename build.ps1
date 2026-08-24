# Windows Event Log - exe paketleme (SQLite, Docker yok)
# Kullanim:  .\build.ps1
# Cikti:     dist\WindowsEventLog\

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> Sanal ortam kontrol" -ForegroundColor Cyan
if (-not (Test-Path ".\venv\Scripts\python.exe")) {
    Write-Host "venv yok, olusturuluyor..."
    python -m venv venv
}

& .\venv\Scripts\python.exe -m pip install --upgrade pip
& .\venv\Scripts\python.exe -m pip install -r requirements.txt
& .\venv\Scripts\python.exe -m pip install "pyinstaller>=6.0"

Write-Host "==> Eski build temizleniyor" -ForegroundColor Cyan
Remove-Item -Recurse -Force .\build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\dist\WindowsEventLog -ErrorAction SilentlyContinue

Write-Host "==> PyInstaller" -ForegroundColor Cyan
& .\venv\Scripts\python.exe -m PyInstaller --noconfirm --clean WindowsEventLog.spec

$dist = Join-Path $PSScriptRoot "dist\WindowsEventLog"
if (-not (Test-Path "$dist\WindowsEventLog.exe")) {
    throw "Build basarisiz: WindowsEventLog.exe bulunamadi"
}

Copy-Item .\config.ini $dist -Force
Copy-Item .\schema_sqlite.sql $dist -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Portable paket hazir:" -ForegroundColor Green
Write-Host "  $dist"
Write-Host "  Calistir: $dist\WindowsEventLog.exe"
Write-Host ""
Write-Host "Hedef PC gereksinimleri:" -ForegroundColor Yellow
Write-Host "  - Windows 10/11"
Write-Host "  - Docker GEREKMEZ (gomulu SQLite)"
Write-Host "  - Security loglari icin Yonetici olarak calistir"
Write-Host ""

$isccCandidates = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($iscc) {
    Write-Host "==> Inno Setup installer" -ForegroundColor Cyan
    & $iscc .\installer\setup.iss
    Write-Host "Setup: dist\WindowsEventLog-Setup.exe" -ForegroundColor Green
} else {
    Write-Host "Inno Setup yok - sadece portable klasor olusturuldu." -ForegroundColor DarkYellow
    Write-Host "Installer icin: https://jrsoftware.org/isinfo.php" -ForegroundColor DarkYellow
    Write-Host "Sonra tekrar: .\build.ps1" -ForegroundColor DarkYellow
}
