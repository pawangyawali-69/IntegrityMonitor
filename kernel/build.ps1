$projDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$wdkDir = Join-Path $projDir "wdk"
$srcFile = Join-Path $projDir "IntegrityMonitor.c"
$objFile = Join-Path $projDir "IntegrityMonitor.obj"
$sysFile = Join-Path $projDir "IntegrityMonitor.sys"

# Find VC++ dev environment
$vcvars = @(
    "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $vcvars) {
    Write-Error "Visual Studio 2022 not found"
    exit 1
}

Write-Host "Setting up Visual Studio environment..."
$env:VSCMD_ARG_TGT_ARCH = "x64"
& cmd /c "call `"$vcvars`" > nul 2>&1 && set" | ForEach-Object {
    if ($_ -match '^(\w+)=(.*)$') {
        Set-Item -Path "env:$($matches[1])" -Value $matches[2]
    }
}

$includeFlags = "/I`"$wdkDir\include\km`" /I`"$wdkDir\include\shared`" /I`"$wdkDir\include\um`""

Write-Host "Compiling IntegrityMonitor.c..."
$clResult = & cl.exe /nologo /c /O1 /W4 /WX /Gz /kernel /Zp8 /GS- `
    /DDRIVER /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 `
    $includeFlags `
    `"$srcFile"`
if ($LASTEXITCODE -ne 0) { Write-Error "Compilation failed"; exit 1 }

Write-Host "Linking IntegrityMonitor.sys..."
& link.exe /nologo /driver /kernel /subsystem:native `
    /entry:DriverEntry@8 `
    /out:`"$sysFile`" `
    `"$objFile`" `
    `"$wdkDir\lib\ntoskrnl.lib`" `
    `"$wdkDir\lib\hal.lib`"
if ($LASTEXITCODE -ne 0) { Write-Error "Linking failed"; exit 1 }

Write-Host "`nSuccess! IntegrityMonitor.sys built."
Get-Item $sysFile | Select-Object Name, Length
