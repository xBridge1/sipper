param(
    [string]$Version = "1.0.1",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Icon = Join-Path $ProjectRoot "build-assets\sipper.ico"
$VersionFile = Join-Path $ProjectRoot "build-assets\version.txt"

if (-not (Test-Path $Python)) {
    throw "Ambiente virtual nao encontrado em $Python"
}

Push-Location $ProjectRoot
try {
    & $Python -m pip install -r requirements.txt -r requirements-build.txt
    & $Python packaging\create_icon.py $Icon
    Set-Content -Path $VersionFile -Value $Version -NoNewline -Encoding ascii
    & $Python -m PyInstaller --noconfirm --clean --windowed --onedir --name SIPPER --icon $Icon --add-data "logo;logo" --add-data "build-assets\version.txt;." ciper\gui_main.py

    if (-not $SkipInstaller) {
        $Compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($null -eq $Compiler) {
            $CandidatePaths = @(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
            )
            $CompilerPath = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($CompilerPath) {
                & $CompilerPath "/DMyAppVersion=$Version" (Join-Path $PSScriptRoot "SIPPER.iss")
                return
            }
        }
        if ($null -eq $Compiler) {
            throw "Inno Setup nao foi encontrado. Instale-o ou execute novamente com -SkipInstaller."
        }
        & $Compiler.Source "/DMyAppVersion=$Version" (Join-Path $PSScriptRoot "SIPPER.iss")
    }
}
finally {
    Pop-Location
}
