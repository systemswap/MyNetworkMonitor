<#
.SYNOPSIS
    Baut MyNetworkMonitor unter Windows nach .\published\ - Gegenstueck zu publish.sh (Vorbild; Aufruf und Ablauf gleich).

.DESCRIPTION
    Erstellt die fertigen Programme in published\:

        published\windows-x64\MyNetworkMonitor.exe          eine Datei: Programm, .NET und Avalonia
        published\linux-x64\MyNetworkMonitor.Avalonia       Linux-Programm als eine Datei (ohne AppImage - die baut nur publish.sh unter Linux)
        published\MyNetworkMonitor-windows-x64.zip

    Neben jedes Programm kommen LICENSE, THIRD-PARTY-NOTICES.md und licenses\, dazu die Herstellerliste (MacVendors\) und die
    Bibliothek der 3D-Ansicht (3dForceGraphLib\), die das Programm neben seiner Programmdatei liest. Unter Linux ausserdem
    einrichten.sh / entfernen.sh fuer den Menueintrag; sie finden die Programmdatei auch ohne AppImage.

    Vor dem Bau laufen die Tests (MyNetworkMonitor.Core.Tests): ein kaputter Stand landet nicht in published\.

    Paketform (Bauart):
      dotnet   eine Datei mit .NET (Standard). Native AOT geht hier nicht (siehe publish.sh).
      einzeln  alle Bibliotheken lose im Ordner (Fehlersuche).

    Aufruf ohne Argumente fragt erst nach der Paketform, dann nach dem Ziel. Mit Argumenten ohne Rueckfrage, Reihenfolge
    egal; was fehlt, gilt als Standard (Paketform dotnet, Ziel beides):
      .\publish.ps1 [linux|windows|beides] [dotnet|einzeln]
      z. B. .\publish.ps1 windows   .\publish.ps1 windows einzeln   .\publish.ps1 beides

    Benoetigt: .NET SDK 10.

.EXAMPLE
    .\publish.ps1
    .\publish.ps1 windows
#>
# Bewusst ohne param-Block: die Woerter kommen wie bei publish.sh in beliebiger Reihenfolge in $args an
$Argumente = @($args | ForEach-Object { [string]$_ })

$ErrorActionPreference = 'Stop'

# dotnet mit Ausgabe in eine Logdatei; liefert den Rueckgabewert. Waehrenddessen eine Statuszeile mit der Laufzeit, bei Tests
# (-Tests) dazu die Zahl der fertigen, fehlgeschlagenen und uebersprungenen Tests - sonst saehe man minutenlang nichts.
function Invoke-Logged([string]$log, [string[]]$arguments, [switch]$Tests) {
    $line = ($arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $errors = "$log.stderr"
    $process = Start-Process dotnet -ArgumentList $line -NoNewWindow -PassThru -RedirectStandardOutput $log -RedirectStandardError $errors
    $null = $process.Handle   # sonst liefert Windows PowerShell 5.1 danach keinen ExitCode
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $process.WaitForExit(1000)) {
        $text = ''
        try {
            $stream = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
            try { $text = (New-Object System.IO.StreamReader($stream)).ReadToEnd() } finally { $stream.Dispose() }
        }
        catch { }
        # Bauen: der letzte Schritt aus dem Log (Projekt fertig ...), damit man sieht, dass es weitergeht
        $last = @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^(warning|Warnung)' })
        $step = if ($last.Count -gt 0) { $last[-1] -replace '^.*\\([^\\]+\.(dll|exe))$', '$1' } else { 'startet' }
        if ($step.Length -gt 52) { $step = $step.Substring(0, 49) + '...' }
        $status = '   {0:mm\:ss}  {1}' -f $watch.Elapsed, $step
        if ($Tests) {
            $passed = [regex]::Matches($text, '(?m)^\s+(Bestanden|Passed)\s').Count
            $failed = [regex]::Matches($text, '(?m)^\s+(Fehler|Failed)\s').Count
            $skipped = [regex]::Matches($text, '(?m)^\s+(.bersprungen|Skipped)\s').Count
            $status = if ($passed + $failed + $skipped -eq 0) { '   baut und startet die Tests ... {0:mm\:ss}' -f $watch.Elapsed }
                      else { '   {0} bestanden, {1} fehlgeschlagen, {2} uebersprungen ... {3:mm\:ss}' -f $passed, $failed, $skipped, $watch.Elapsed }
        }
        Write-Host -NoNewline ("`r" + $status.PadRight(78))
    }
    $process.WaitForExit()
    Write-Host -NoNewline ("`r" + ''.PadRight(78) + "`r")
    if (Test-Path $errors) {
        Get-Content $errors | Add-Content $log
        Remove-Item $errors -Force
    }
    return $process.ExitCode
}

# Keine Nutzungsdaten an Microsoft (.NET) oder Avalonia senden.
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$env:TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'
$env:DO_NOT_TRACK = '1'
$env:DOTNET_NOLOGO = '1'

$root       = $PSScriptRoot
$project    = Join-Path $root 'MyNetworkMonitor.Avalonia\MyNetworkMonitor.Avalonia.csproj'
$tests      = Join-Path $root 'MyNetworkMonitor.Core.Tests\MyNetworkMonitor.Core.Tests.csproj'
$outDir     = Join-Path $root 'published'
$linuxDir   = Join-Path $outDir 'linux-x64'
$windowsDir = Join-Path $outDir 'windows-x64'
$cacheDir   = Join-Path $env:LOCALAPPDATA 'mynetworkmonitor-build'
$workDir    = Join-Path $cacheDir 'publish'
$artifacts  = Join-Path $cacheDir 'artifacts'
$tarExe     = Join-Path $env:SystemRoot 'System32\tar.exe'
$assembly   = 'MyNetworkMonitor.Avalonia'

$Target = ''
$Bauart = ''
foreach ($argument in @($Argumente | Where-Object { $_ })) {
    switch ($argument.ToLowerInvariant()) {
        { $_ -in 'linux', 'windows' } { $Target = $_; break }
        { $_ -in 'beides', 'all' } { $Target = 'all'; break }
        { $_ -in 'dotnet', 'net', 'eine-datei', 'datei' } { $Bauart = 'dotnet'; break }
        { $_ -in 'einzeln', 'ordner' } { $Bauart = 'einzeln'; break }
        default { throw "Aufruf: .\publish.ps1 [linux|windows|beides] [dotnet|einzeln]" }
    }
}

if (@($Argumente | Where-Object { $_ }).Count -gt 0) {
    # Mit Argumenten nie nachfragen
    if (-not $Target) { $Target = 'all' }
    if (-not $Bauart) { $Bauart = 'dotnet' }
}

function Read-Choice([string]$question, [string[]]$options, [string[]]$values) {
    Write-Host ''
    Write-Host $question
    for ($i = 0; $i -lt $options.Count; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $options[$i]) }
    Write-Host ''
    $answer = Read-Host 'Auswahl [1]'
    if (-not $answer) { $answer = '1' }
    $index = 0
    if (-not [int]::TryParse($answer, [ref]$index) -or $index -lt 1 -or $index -gt $values.Count) { throw 'Ungueltige Auswahl.' }
    return $values[$index - 1]
}

if (-not $Bauart) {
    $Bauart = Read-Choice 'Welche Paketform?' `
        @('Eine Datei (Standard) - Windows: EXE, Linux: Programmdatei; .NET und Avalonia darin',
          'Einzeln               - alle Bibliotheken lose im Ordner (Fehlersuche)') `
        @('dotnet', 'einzeln')
}
if (-not $Target) {
    $Target = Read-Choice 'Wofuer soll gebaut werden?' @('beides (Standard)', 'Linux', 'Windows') @('all', 'linux', 'windows')
}

$single = if ($Bauart -eq 'einzeln') { 'false' } else { 'true' }
Write-Host "Ziel: $Target, Bauart: $Bauart"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Fehler: .NET SDK fehlt.' }
# Nicht, solange das Programm aus published\ laeuft.
function Assert-NotRunning {
    $running = Get-Process MyNetworkMonitor, $assembly -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($outDir, [StringComparison]::OrdinalIgnoreCase) }
    if ($running) { throw "Fehler: MyNetworkMonitor laeuft gerade (aus published\) - bitte erst beenden, dann neu bauen." }
}
Assert-NotRunning

[xml]$csproj = Get-Content $project
$version = ([string]($csproj.Project.PropertyGroup.Version | Where-Object { $_ })).Trim()
Write-Host "MyNetworkMonitor $version"

# Alte Zwischenstaende weg; was noch gesperrt ist (Build-Server von dotnet halten Logs eines frueheren Laufs offen), bleibt liegen -
# die Logs tragen deshalb einen Zeitstempel
if (Test-Path $workDir) { Get-ChildItem $workDir -Force | ForEach-Object { try { Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop } catch { } } }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $workDir, $outDir | Out-Null

# Ein kaputter Stand soll nicht in published\ landen (wie der GitHub-Bau).
Write-Host '== Tests'
$testLog = Join-Path $workDir "test-$stamp.log"
$code = Invoke-Logged $testLog @('test', $tests, '-c', 'Release', '-p:UseArtifactsOutput=true', "-p:ArtifactsPath=$artifacts",
    '--logger', 'console;verbosity=normal') -Tests
if ($code -ne 0) {
    Get-Content $testLog -Tail 30 | Write-Host
    throw 'Fehler: Tests fehlgeschlagen - nichts veroeffentlicht.'
}
Select-String -Path $testLog -Pattern '^\s*(Gesamtzahl Tests|Total tests|Bestanden|Passed|Nicht bestanden|Failed|.bersprungen|Skipped):' | ForEach-Object { Write-Host "   $($_.Line.Trim())" }

# Lizenz, Hinweise auf fremde Bestandteile und deren Lizenztexte neben das Programm.
function Copy-Notices([string]$dest) {
    Copy-Item (Join-Path $root 'LICENSE') $dest -Force
    Copy-Item (Join-Path $root 'THIRD-PARTY-NOTICES.md') $dest -Force
    $licenses = Join-Path $dest 'licenses'
    if (Test-Path $licenses) { Remove-Item $licenses -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $licenses | Out-Null
    Copy-Item (Join-Path $root 'licenses\*') $licenses -Force
}

function Clear-ProgramFolder([string]$dest) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Get-ChildItem $dest -Force | Remove-Item -Recurse -Force
}

function Invoke-Publish([string]$rid, [string]$dest, [string[]]$properties) {
    $log = Join-Path $workDir "publish-$rid-$stamp.log"
    $code = Invoke-Logged $log (@('publish', $project, '-c', 'Release', '-r', $rid, '--self-contained', 'true') + $properties +
        @("-p:PublishSingleFile=$single", "-p:IncludeNativeLibrariesForSelfExtract=$single", "-p:EnableCompressionInSingleFile=$single",
          '-p:DebugType=None', '-p:DebugSymbols=false', '-p:UseArtifactsOutput=true', "-p:ArtifactsPath=$artifacts", '-o', $dest))
    if ($code -ne 0) {
        Get-Content $log -Tail 20 | Write-Host
        throw "Fehler: dotnet publish fuer $rid fehlgeschlagen."
    }
    Get-ChildItem $dest -Recurse -Include *.pdb | Remove-Item -Force
    if (-not (Test-Path (Join-Path $dest 'MacVendors\mac_vendors.csv')) -or -not (Test-Path (Join-Path $dest '3dForceGraphLib\3d-force-graph.min.js'))) {
        throw "Fehler: MacVendors\ oder 3dForceGraphLib\ fehlt in der Ausgabe fuer $rid."
    }
}

# Paket mit dem Ordner selbst als oberster Ebene (wie publish.sh). tar.exe von Windows schreibt Zip mit -a.
function New-Package([string]$folder, [string]$archive) {
    $path = Join-Path $outDir $archive
    if (Test-Path $path) { Remove-Item $path -Force }
    # Die frisch kopierte EXE haelt kurz ein anderer Prozess fest (vermutlich der Virenscanner)
    for ($try = 1; ; $try++) {
        & $tarExe -a -c -f $path -C $outDir $folder
        if ($LASTEXITCODE -eq 0) { break }
        if ($try -ge 6) { throw "Fehler: Paket $archive fehlgeschlagen." }
        Write-Host "   Paket: Datei noch gesperrt, neuer Versuch in 5 s ($try/5) ..."
        Start-Sleep -Seconds 5
    }
}

# ---------------------------------------------------------------- Linux
if ($Target -in @('all', 'linux')) {
    Write-Host '== Linux'
    $build = Join-Path $workDir 'linux'
    # Die csproj waehlt auf einem Windows-Rechner sonst net10.0-windows samt Windows-Teilen, auch fuer linux-x64
    Invoke-Publish 'linux-x64' $build @('-p:MnmWindowsBuild=false')
    Assert-NotRunning
    Clear-ProgramFolder $linuxDir
    # Keine AppImage und kein tar.gz: appimagetool laeuft nur unter Linux, und Windows kann das Ausfuehrrecht nicht setzen
    Copy-Item (Join-Path $build '*') $linuxDir -Recurse -Force
    Copy-Notices $linuxDir
    Copy-Item (Join-Path $root 'packaging\linux\mynetworkmonitor.png') $linuxDir -Force
    # LF-Zeilenenden erzwingen, sonst scheitern die Skripte unter Linux an \r
    foreach ($name in @('einrichten.sh', 'entfernen.sh')) {
        $text = [System.IO.File]::ReadAllText((Join-Path $root "packaging\linux\$name")) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText((Join-Path $linuxDir $name), $text, (New-Object System.Text.UTF8Encoding $false))
    }
    Write-Host "   Unter Linux: chmod +x $assembly einrichten.sh entfernen.sh; ./einrichten.sh"
}

# ---------------------------------------------------------------- Windows
if ($Target -in @('all', 'windows')) {
    Write-Host '== Windows'
    $build = Join-Path $workDir 'windows'
    Invoke-Publish 'win-x64' $build @()
    Assert-NotRunning
    Clear-ProgramFolder $windowsDir
    if ($single -eq 'true') {
        Copy-Item (Join-Path $build "$assembly.exe") (Join-Path $windowsDir 'MyNetworkMonitor.exe') -Force
        Copy-Item (Join-Path $build 'MacVendors'), (Join-Path $build '3dForceGraphLib') $windowsDir -Recurse -Force
    }
    else { Copy-Item (Join-Path $build '*') $windowsDir -Recurse -Force }
    Copy-Notices $windowsDir
    New-Package 'windows-x64' 'MyNetworkMonitor-windows-x64.zip'
}

Write-Host ''
Write-Host "Fertig (MyNetworkMonitor $version):"
Get-ChildItem $outDir -Recurse -File -Depth 2 |
    Where-Object { $_.Extension -in @('.exe', '.zip', '.AppImage', '.gz') -or $_.Name -eq $assembly } |
    Sort-Object FullName |
    ForEach-Object { Write-Host ("  {0}  ({1:N0} Bytes)" -f $_.FullName.Substring($outDir.Length + 1).Replace('\', '/'), $_.Length) }
