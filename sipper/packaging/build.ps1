param(
    [string]$Version = "1.2.0",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Icon = Join-Path $ProjectRoot "build-assets\sipper.ico"
$VersionFile = Join-Path $ProjectRoot "build-assets\version.txt"

function Invoke-InstallerSigning {
    param([string]$InstallerPath)

    if (-not $env:SIPPER_SIGN_CERTIFICATE) {
        return
    }

    $SignTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -eq $SignTool) {
        throw "signtool.exe nao foi encontrado para assinar o instalador."
    }

    $Arguments = @("sign", "/fd", "SHA256", "/f", $env:SIPPER_SIGN_CERTIFICATE)
    if ($env:SIPPER_SIGN_PASSWORD) {
        $Arguments += @("/p", $env:SIPPER_SIGN_PASSWORD)
    }
    if ($env:SIPPER_TIMESTAMP_URL) {
        $Arguments += @("/tr", $env:SIPPER_TIMESTAMP_URL, "/td", "SHA256")
    }
    $Arguments += $InstallerPath

    & $SignTool.Source @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao assinar o instalador SIPPER."
    }
}

function Write-InstallerChecksum {
    param([string]$InstallerPath)

    $ChecksumPath = "$InstallerPath.sha256"
    $Hash = (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -Path $ChecksumPath -Value "$Hash  $(Split-Path -Leaf $InstallerPath)" -NoNewline -Encoding ascii
    Write-Host "Checksum SHA-256 criado: $ChecksumPath"
}

if (-not (Test-Path $Python)) {
    throw "Ambiente virtual nao encontrado em $Python"
}

Push-Location $ProjectRoot
try {
    & $Python -m pip install -r requirements.txt -r requirements-build.txt
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao instalar as dependencias de build."
    }
    & $Python packaging\create_icon.py $Icon
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao gerar o icone do instalador."
    }
    Set-Content -Path $VersionFile -Value $Version -NoNewline -Encoding ascii
    & $Python -m PyInstaller --noconfirm --clean --windowed --onedir --name SIPPER --icon $Icon --add-data "logo;logo" --add-data "build-assets\version.txt;." ciper\gui_main.py
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao gerar o executavel SIPPER."
    }

    if (-not $SkipInstaller) {
        $Compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        $CompilerPath = $null
        if ($null -eq $Compiler) {
            $CandidatePaths = @(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
            )
            $CompilerPath = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        }

        if ($null -eq $Compiler -and -not $CompilerPath) {
            throw "Inno Setup nao foi encontrado. Instale-o ou execute novamente com -SkipInstaller."
        }

        $CompilerExecutable = if ($CompilerPath) { $CompilerPath } else { $Compiler.Source }
        & $CompilerExecutable "/DMyAppVersion=$Version" (Join-Path $PSScriptRoot "SIPPER.iss")
        if ($LASTEXITCODE -ne 0) {
            throw "Falha ao criar o instalador Inno Setup."
        }

        $InstallerPath = Join-Path $ProjectRoot "dist-installer\SIPPER-Setup-$Version.exe"
        if (-not (Test-Path $InstallerPath)) {
            throw "Instalador nao encontrado apos a compilacao: $InstallerPath"
        }
        Invoke-InstallerSigning $InstallerPath
        Write-InstallerChecksum $InstallerPath
    }
}
finally {
    Pop-Location
}
