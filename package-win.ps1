
<#
package-win.ps1 — Build + package Miqrochain GUI for Windows

Prereqs:
- Qt 6 (same kit you used to build GUI), path to windeployqt.exe
- Inno Setup 6 (ISCC.exe in PATH or default install path)
- Built binaries:
    - GUI:   .\build-gui\Release\miqro-gui.exe
    - Daemon .\build\Release\miqrod.exe
#>

param(
  [string]$QtBin = "C:\Qt\6.6.2\msvc2019_64\bin",
  [string]$GuiExe = ".\build-gui\Release\miqro-gui.exe",
  [string]$DaemonExe = ".\build\Release\miqrod.exe",
  [string]$Staging = ".\dist\Miqrochain",
  [string]$Inno = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
  [string]$OpenSslDir = "C:\Qt\Tools\OpenSSL\Win_x64\bin"  # adjust if needed
)

$ErrorActionPreference = "Stop"

# 1) Clean staging
if (Test-Path $Staging) { Remove-Item -Recurse -Force $Staging }
New-Item -ItemType Directory -Force -Path $Staging | Out-Null

# 2) Copy binaries
Copy-Item $GuiExe $Staging
Copy-Item $DaemonExe $Staging

# 3) Run windeployqt to pull Qt runtime
$windeploy = Join-Path $QtBin "windeployqt.exe"
if (!(Test-Path $windeploy)) { throw "windeployqt not found at $windeploy" }

& $windeploy --release --compiler-runtime --network --no-quick-import `
   --dir $Staging $GuiExe

# 4) Ensure OpenSSL 3 DLLs exist (QtNetwork TLS needs them)
$ssl1 = Join-Path $OpenSslDir "libssl-3-x64.dll"
$ssl2 = Join-Path $OpenSslDir "libcrypto-3-x64.dll"
if (Test-Path $ssl1 -PathType Leaf) { Copy-Item $ssl1 $Staging -Force }
if (Test-Path $ssl2 -PathType Leaf) { Copy-Item $ssl2 $Staging -Force }

# 5) Verify essentials
$need = @("miqro-gui.exe","miqrod.exe","Qt6Core.dll","Qt6Gui.dll","Qt6Widgets.dll","Qt6Network.dll","platforms\qwindows.dll")
foreach($n in $need){
  $p = Join-Path $Staging $n
  if (!(Test-Path $p)) { Write-Warning "Missing: $n (check windeployqt output)" }
}

# 6) Build installer via Inno Setup
$iss = ".\miqro_gui_installer.iss"
if (!(Test-Path $iss)) { throw "Installer script not found: $iss" }

& $Inno $iss

Write-Host "Done. Look in dist\installer for the installer EXE." -ForegroundColor Green
