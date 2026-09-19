# CI only: creates a temporary standard account on a disposable GitHub runner.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows') {
    throw 'Run this account-isolation test only on a disposable GitHub-hosted Windows runner.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$build = Join-Path $repoRoot 'build'
$framework = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'
# build.ps1 has already validated this fixed compiler. Recheck before reuse.
$sig = Get-AuthenticodeSignature -LiteralPath $compiler
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
    throw 'Microsoft compiler signature verification failed.'
}
& $compiler /nologo /noconfig /target:exe "/reference:$(Join-Path $framework 'System.dll')" "/out:$(Join-Path $build 'PreviewTests.exe')" (Join-Path $PSScriptRoot 'PreviewTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Could not compile the standard-user test driver.' }

$testRoot = Join-Path $env:RUNNER_TEMP ('tron-preview-' + [Guid]::NewGuid().ToString('N'))
$bin = Join-Path $testRoot 'bin'
[void](New-Item -ItemType Directory -Path $bin)
foreach ($name in @('TronDirectEnforcer.exe','TronDirectEnforcerPureTests.exe','PreviewTests.exe')) {
    Copy-Item -LiteralPath (Join-Path $build $name) -Destination (Join-Path $bin $name)
}
$accountName = 'trontest' + [Guid]::NewGuid().ToString('N').Substring(0,10)
$password = ConvertTo-SecureString ([Guid]::NewGuid().ToString('N') + '!aA2') -AsPlainText -Force
$created = $false
$process = $null
try {
    $account = New-LocalUser -Name $accountName -Password $password -Description 'Disposable TRON CI refusal tests'
    $created = $true
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users -Member $account
    $acl = Get-Acl -LiteralPath $testRoot
    $access = New-Object System.Security.AccessControl.FileSystemAccessRule($account.SID, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($access)
    Set-Acl -LiteralPath $testRoot -AclObject $acl
    $credentials = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$accountName", $password)
    $stdout = Join-Path $testRoot 'stdout.json'
    $stderr = Join-Path $testRoot 'stderr.txt'
    $process = Start-Process -FilePath (Join-Path $bin 'PreviewTests.exe') -Credential $credentials -LoadUserProfile -WorkingDirectory $bin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(120000)) { Stop-Process -Id $process.Id -Force; throw 'Preview test driver timed out.' }
    $process.WaitForExit()
    $reportText = [IO.File]::ReadAllText($stdout).Trim()
    $errorText = [IO.File]::ReadAllText($stderr).Trim()
    if ($process.ExitCode -ne 0 -or $errorText.Length -ne 0) { throw "Preview tests failed: $errorText" }
    $report = $reportText | ConvertFrom-Json
    if ($report.status -ne 'PREVIEW_TESTS_PASSED' -or $report.pureTestsPassed -lt 1 -or
        $report.windowsRefusalTestsPassed -ne 8 -or -not $report.standardUserTokenVerified -or
        $report.firewallRulesCreated -or $report.installed) { throw 'Unexpected preview test report.' }
    $results = Join-Path $repoRoot 'ci-results'
    [void](New-Item -ItemType Directory -Path $results)
    [IO.File]::WriteAllText((Join-Path $results 'tests.json'), $reportText + "`n", (New-Object Text.UTF8Encoding($false)))
    Write-Output $reportText
} finally {
    if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    if ($created) { Remove-LocalUser -Name $accountName }
    $password.Dispose()
}
