# Downloads tunel for this Windows computer, checks it, and sets it up:
#
#   irm https://raw.githubusercontent.com/matrixdurden/tunel/main/install.ps1 | iex
#
# It asks for the link from your server (or Enter for DPI bypass only); if
# tunel is already set up it updates it instead. tunel installs itself to C:\Program Files\tunel;
# `tunel remove` takes everything away again.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # the progress bar makes downloads very slow in Windows PowerShell
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $base = 'https://github.com/matrixdurden/tunel/releases/latest/download'
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $file = "tunel-windows-$arch.exe"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("tunel-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $tmp | Out-Null
    $exe = Join-Path $tmp 'tunel.exe'

    try {
        Invoke-WebRequest -UseBasicParsing "$base/$file" -OutFile $exe
        $sums = (Invoke-WebRequest -UseBasicParsing "$base/checksums.txt").Content
        if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
        $want = ($sums -split "`n" | Where-Object { $_ -match " $([regex]::Escape($file))\s*$" } | Select-Object -First 1) -replace '\s.*$', ''
        $got = (Get-FileHash $exe -Algorithm SHA256).Hash
        if (-not $want -or $got -ne $want) { throw "checksum mismatch; nothing was installed" }

        $installed = [bool](Get-Service tunel -ErrorAction SilentlyContinue)
        if ($installed) { & $exe update } else { & $exe client }
        if ($LASTEXITCODE -eq 0) {
            # New terminals find tunel through PATH; make this one find it too.
            $dir = Join-Path $env:ProgramFiles 'tunel'
            if (($env:Path -split ';') -notcontains $dir) { $env:Path += ";$dir" }
        }
    }
    catch {
        Write-Host "tunel: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
