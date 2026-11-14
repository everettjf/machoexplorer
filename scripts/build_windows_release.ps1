Param(
    [string]$Version = "",
    [string]$Tag = "",
    [string]$Repo = "",
    [string]$ISCCPath = "",
    [switch]$SkipTests,
    [switch]$SkipUpload,
    [switch]$NoClobber
)

$ErrorActionPreference = "Stop"

function Require-Command([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $name"
    }
}

function Get-WorkspaceVersion([string]$cargoToml) {
    $line = Select-String -Path $cargoToml -Pattern '^version = "([^"]+)"' | Select-Object -First 1
    if (-not $line) {
        throw "Failed to parse workspace version from $cargoToml"
    }
    return $line.Matches[0].Groups[1].Value
}

Require-Command gh

$root = Split-Path -Parent $PSScriptRoot
$stagePath = Join-Path $root "dist/windows/MachOExplorer"
$installerDir = Join-Path $root "dist/windows/installer"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-WorkspaceVersion (Join-Path $root "Cargo.toml")
}
if ([string]::IsNullOrWhiteSpace($Tag)) {
    $Tag = "v$Version"
}

if ($Repo) {
    $repoArgs = @("--repo", $Repo)
} else {
    $repoArgs = @()
}

gh auth status | Out-Null
gh release view $Tag @repoArgs | Out-Null

$installerArgs = @{ Version = $Version }
if (-not [string]::IsNullOrWhiteSpace($ISCCPath)) {
    $installerArgs["ISCCPath"] = $ISCCPath
}
if ($SkipTests) {
    $installerArgs["SkipTests"] = $true
}

& (Join-Path $PSScriptRoot "build_windows_installer.ps1") @installerArgs

$portableZip = Join-Path $root ("dist/windows/MachOExplorer-{0}-windows-x64-portable.zip" -f $Version)
$installerExe = Join-Path $installerDir ("MachOExplorer-Setup-{0}.exe" -f $Version)

if (!(Test-Path $stagePath)) {
    throw "Staged app directory not found: $stagePath"
}
if (!(Test-Path $installerExe)) {
    throw "Installer not found: $installerExe"
}

if (Test-Path $portableZip) {
    Remove-Item -Force $portableZip
}
Compress-Archive -Path (Join-Path $stagePath "*") -DestinationPath $portableZip

Write-Host "Windows assets ready:"
Write-Host "  portable zip: $portableZip"
Write-Host "  installer   : $installerExe"

if ($SkipUpload) {
    Write-Host "Skipping GitHub release upload."
    exit 0
}

$uploadArgs = @("release", "upload", $Tag, $portableZip, $installerExe)
$uploadArgs += $repoArgs
if (-not $NoClobber) {
    $uploadArgs += "--clobber"
}

gh @uploadArgs

Write-Host "Uploaded Windows assets to GitHub release $Tag"
