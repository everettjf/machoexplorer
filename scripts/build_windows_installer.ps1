# Build the Rust GUI + CLI on Windows, stage them, and build the Inno Setup
# installer.
#
#   powershell -ExecutionPolicy Bypass -File scripts/build_windows_installer.ps1
#
# Requirements: Rust (MSVC toolchain) and Inno Setup 6.
Param(
    [string]$Version = "",
    [string]$ISCCPath = "",
    [switch]$SkipTests,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"

function Resolve-ToolPath([string]$preferred, [string]$commandName, [string[]]$candidates = @()) {
    if (-not [string]::IsNullOrWhiteSpace($preferred)) {
        if (!(Test-Path $preferred)) {
            throw "$commandName not found: $preferred"
        }
        return (Resolve-Path $preferred).Path
    }
    $command = Get-Command $commandName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "Missing required command: $commandName"
}

function Get-WorkspaceVersion([string]$cargoToml) {
    $line = Select-String -Path $cargoToml -Pattern '^version = "([^"]+)"' | Select-Object -First 1
    if (-not $line) {
        throw "Failed to parse workspace version from $cargoToml"
    }
    return $line.Matches[0].Groups[1].Value
}

function Invoke-Checked([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$exe $($arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

$root = Split-Path -Parent $PSScriptRoot
$cargo = Resolve-ToolPath "" "cargo" @((Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"))
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-WorkspaceVersion (Join-Path $root "Cargo.toml")
}

Push-Location $root
try {
    # Statically link the C runtime so the installer needs no VC++ redistributable.
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    if (-not $SkipTests) {
        Invoke-Checked $cargo @("test", "--locked", "-p", "moex-core", "-p", "moex-cli")
    }
    Invoke-Checked $cargo @("build", "--release", "--locked", "-p", "moex-app", "-p", "moex-cli")
} finally {
    Pop-Location
}

$stagePath = Join-Path $root "dist/windows/MachOExplorer"
if (Test-Path $stagePath) {
    Remove-Item -Recurse -Force $stagePath
}
New-Item -ItemType Directory -Force -Path $stagePath | Out-Null
Copy-Item (Join-Path $root "target/release/MachOExplorer.exe") $stagePath
Copy-Item (Join-Path $root "target/release/moex.exe") $stagePath
Copy-Item (Join-Path $root "LICENSE") $stagePath
Write-Host "staged: $stagePath (version $Version)"

if ($SkipInstaller) {
    return
}

$iscc = Resolve-ToolPath $ISCCPath "iscc" @(
    "D:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)
$iss = Join-Path $root "packaging/windows/MachOExplorer.iss"
Invoke-Checked $iscc @("/DMyAppVersion=$Version", "/DMyAppSourceRoot=$stagePath", $iss)
Write-Host "installer: $(Join-Path $root "dist/windows/installer/MachOExplorer-Setup-$Version.exe")"
