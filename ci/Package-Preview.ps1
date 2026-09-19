[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:GITHUB_REPOSITORY -ne 'volong99-stack/Tron-Direct-Enforcement' -or
    $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$') { throw 'A recorded GitHub build of this repository is required.' }
$root = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content -LiteralPath (Join-Path $root 'RELEASE-FILES.json') -Raw | ConvertFrom-Json
$tests = Get-Content -LiteralPath (Join-Path $root 'ci-results\tests.json') -Raw | ConvertFrom-Json
if ($tests.status -ne 'PREVIEW_TESTS_PASSED' -or -not $tests.standardUserTokenVerified -or
    $tests.pureTestsPassed -lt 1 -or $tests.windowsRefusalTestsPassed -ne 8) { throw 'Passing preview tests are required.' }
$config = Get-Content -LiteralPath (Join-Path $root 'config.disabled.example.json') -Raw | ConvertFrom-Json
if ($config.authorizationEnabled -or $config.allowedProgramPaths.Count -ne 0 -or
    @($config.programSha256Pins.PSObject.Properties).Count -ne 0) { throw 'Preview configuration must remain disabled with empty pins.' }
$dist = Join-Path $root 'dist'
if (Test-Path -LiteralPath $dist) { throw 'Refusing to overwrite an existing preview.' }
$stage = Join-Path $dist 'stage'
[void](New-Item -ItemType Directory -Path $stage)
$allowed = @('TronDirectEnforcer.exe','TronDirectEnforcerPureTests.exe','LICENSE','README.md','PREVIEW.md','config.disabled.example.json','VALIDATION.json')
if (@(Compare-Object $allowed @($manifest.previewArchiveFiles)).Count -ne 0) { throw 'Preview manifest differs from the reviewed file set.' }
foreach ($name in @('TronDirectEnforcer.exe','TronDirectEnforcerPureTests.exe')) {
    $source = Join-Path (Join-Path $root 'build') $name
    if ((Get-AuthenticodeSignature -LiteralPath $source).Status -ne 'NotSigned') { throw 'Unexpected signing state: review the release policy.' }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $name)
}
foreach ($name in @('LICENSE','README.md','PREVIEW.md','config.disabled.example.json')) {
    Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path $stage $name)
}
$validation = [ordered]@{
    schemaVersion = 1
    status = 'UNSIGNED_DEVELOPER_PREVIEW_NOT_FOR_PRODUCTION'
    sourceCommit = $env:GITHUB_SHA
    workflowRun = "https://github.com/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
    pureTestsPassed = $tests.pureTestsPassed
    windowsRefusalTestsPassed = $tests.windowsRefusalTestsPassed
    standardUserTokenVerified = $true
    authenticodeSigned = $false
    nativeFirewallLifecycleValidated = $false
    authenticatedDualReviewIntegrationValidated = $false
    productionReady = $false
}
[IO.File]::WriteAllText((Join-Path $stage 'VALIDATION.json'), ($validation | ConvertTo-Json -Depth 4) + "`n", (New-Object Text.UTF8Encoding($false)))
if (@(Compare-Object $allowed @(Get-ChildItem -LiteralPath $stage -File | Select-Object -ExpandProperty Name)).Count -ne 0) { throw 'Unexpected preview files.' }
$archiveName = 'TRON-developer-preview-' + $env:GITHUB_SHA.Substring(0,12) + '.zip'
$archive = Join-Path $dist $archiveName
Compress-Archive -LiteralPath @($allowed | ForEach-Object { Join-Path $stage $_ }) -DestinationPath $archive -CompressionLevel Optimal
# Inspect the actual ZIP rather than trusting the staging operation.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    if (@(Compare-Object $allowed @($zip.Entries | Select-Object -ExpandProperty FullName)).Count -ne 0) { throw 'Unexpected archive entries.' }
} finally { $zip.Dispose() }
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), "$hash  $archiveName`n", (New-Object Text.UTF8Encoding($false)))
$notes = @"
Unsigned developer preview for source commit $env:GITHUB_SHA.

Validation: $($tests.pureTestsPassed) in-memory tests and $($tests.windowsRefusalTestsPassed) Windows refusal probes passed under a verified standard-user token.

This archive is for code review and controlled development testing. It contains no installer or enabled configuration. Native firewall traffic, cleanup across crashes/reboots, installed privilege isolation, and authenticated review integration remain unvalidated. It is not ready to protect a computer.

Download the ZIP, SHA256SUMS.txt, and attestation.sigstore.json. Verify the ZIP before extracting; see PREVIEW.md in the repository for the exact commands. The GitHub attestation establishes build origin. It is not Windows Authenticode signing and does not remove SmartScreen or Smart App Control restrictions.

Build and tests: https://github.com/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID
"@
[IO.File]::WriteAllText((Join-Path $dist 'release-notes.md'), $notes, (New-Object Text.UTF8Encoding($false)))
Write-Output "Packaged reviewed file set: $archiveName"
