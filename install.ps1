$ErrorActionPreference = 'Stop'
$repo = 'alfa-reza/cvss-calculator-mcp'
$binary = 'cvss-calculator-mcp'
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($arch) {
    'X64' { $arch = 'amd64' }
    'Arm64' { $arch = 'arm64' }
    default { throw "Unsupported Windows architecture: $arch (supported: x64, ARM64)" }
}
$version = $env:VERSION
if (-not $version) {
    $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
}
if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid release version: $version" }
$number = $version.Substring(1)
$name = "${binary}_${number}_windows_${arch}"
$archive = "$name.zip"
$installDir = $env:INSTALL_DIR
if (-not $installDir) { $installDir = Join-Path $env:LOCALAPPDATA 'Programs\cvss-calculator-mcp' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $base = "https://github.com/$repo/releases/download/$version"
    Invoke-WebRequest "$base/$archive" -OutFile (Join-Path $temp $archive)
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $temp 'SHA256SUMS')
    $matches = @(Get-Content (Join-Path $temp 'SHA256SUMS') | Where-Object { $_ -match "^([a-fA-F0-9]{64})  $([regex]::Escape($archive))$" })
    if ($matches.Count -ne 1) { throw 'Checksum entry missing or ambiguous' }
    $expected = $matches[0].Substring(0, 64)
    if ((Get-FileHash (Join-Path $temp $archive) -Algorithm SHA256).Hash -ne $expected) { throw 'Checksum mismatch' }
    Expand-Archive (Join-Path $temp $archive) -DestinationPath $temp
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item (Join-Path $temp "$name\$binary.exe") (Join-Path $installDir "$binary.exe") -Force
    Write-Host "Installed $version to $installDir\$binary.exe"
    Write-Host 'Add this directory to PATH or use the full path in your MCP client.'
} finally {
    Remove-Item -Recurse -Force $temp
}
