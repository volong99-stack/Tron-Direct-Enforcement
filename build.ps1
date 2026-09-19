# Local offline build only. No installation, signing, execution, policy change,
# network request, publisher registration, or upload is performed.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checkedPath = [System.IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($checkedPath)) {
        if (Test-Path -LiteralPath $checkedPath) {
            $item = Get-Item -LiteralPath $checkedPath -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse path is not accepted for this fixed build: $checkedPath"
            }
        }
        $parent = [System.IO.Path]::GetDirectoryName($checkedPath)
        if ($parent -eq $checkedPath) { break }
        $checkedPath = $parent
    }
}

$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($windowsDirectory)) {
    throw 'This fixed build requires Windows with its installed Microsoft .NET Framework compiler.'
}
$frameworkName = if ([Environment]::Is64BitOperatingSystem) { 'Framework64' } else { 'Framework' }
$frameworkDirectory = Join-Path $windowsDirectory "Microsoft.NET\$frameworkName\v4.0.30319"
$compilerPath = Join-Path $frameworkDirectory 'csc.exe'
Assert-NotReparsePoint $compilerPath
if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
    throw 'The fixed installed .NET Framework compiler was not found. No download or fallback will be attempted.'
}

$signature = Get-AuthenticodeSignature -LiteralPath $compilerPath
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $null -eq $signature.SignerCertificate -or
    $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
    throw 'The installed compiler does not have a verified valid Microsoft Authenticode signature.'
}
$compilerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($compilerPath)
if ($compilerVersion.OriginalFilename -ine 'csc.exe' -or
    $compilerVersion.CompanyName -ne 'Microsoft Corporation') {
    throw 'The verified compiler metadata does not identify Microsoft csc.exe.'
}

$sourceDirectory = [System.IO.Path]::GetFullPath($PSScriptRoot)
Assert-NotReparsePoint $sourceDirectory
$nativeSource = Join-Path $sourceDirectory 'TronDirectEnforcer.cs'
$testSource = Join-Path $sourceDirectory 'TronDirectEnforcerPureTests.cs'
$assemblyMetadata = Join-Path $sourceDirectory 'AssemblyInfo.cs'
foreach ($inputFile in @($nativeSource, $testSource, $assemblyMetadata)) {
    Assert-NotReparsePoint $inputFile
    if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) {
        throw "A fixed source file is missing: $inputFile"
    }
}

$references = @('System.dll', 'Microsoft.CSharp.dll', 'System.Core.dll') |
    ForEach-Object { Join-Path $frameworkDirectory $_ }
foreach ($reference in $references) {
    Assert-NotReparsePoint $reference
    if (-not (Test-Path -LiteralPath $reference -PathType Leaf)) {
        throw "A fixed framework reference is missing: $reference"
    }
}

$outputDirectory = Join-Path $sourceDirectory 'build'
Assert-NotReparsePoint $outputDirectory
if (Test-Path -LiteralPath $outputDirectory) {
    throw 'The build output directory already exists. Preserve/review that build separately before a fresh build.'
}
[void][System.IO.Directory]::CreateDirectory($outputDirectory)
$nativeOutput = Join-Path $outputDirectory 'TronDirectEnforcer.exe'
$testOutput = Join-Path $outputDirectory 'TronDirectEnforcerPureTests.exe'

$sharedArguments = @('/nologo', '/noconfig', '/optimize+', '/platform:anycpu')
foreach ($reference in $references) { $sharedArguments += "/reference:$reference" }
$nativeArguments = $sharedArguments + @(
    '/target:winexe',
    "/out:$nativeOutput",
    $nativeSource,
    $assemblyMetadata
)
$nativeLog = & $compilerPath @nativeArguments 2>&1
$nativeExitCode = $LASTEXITCODE
$nativeLog | Out-File -LiteralPath (Join-Path $outputDirectory 'native-compiler.log') -Encoding utf8
if ($nativeExitCode -ne 0 -or -not (Test-Path -LiteralPath $nativeOutput -PathType Leaf)) {
    throw "Native compilation failed with exit code $nativeExitCode. Outputs are retained for review."
}

$testArguments = $sharedArguments + @(
    '/target:exe',
    '/main:TronDirectEnforcerPureTests',
    "/out:$testOutput",
    $nativeSource,
    $testSource,
    $assemblyMetadata
)
$testLog = & $compilerPath @testArguments 2>&1
$testExitCode = $LASTEXITCODE
$testLog | Out-File -LiteralPath (Join-Path $outputDirectory 'test-compiler.log') -Encoding utf8
if ($testExitCode -ne 0 -or -not (Test-Path -LiteralPath $testOutput -PathType Leaf)) {
    throw "Test compilation failed with exit code $testExitCode. Outputs are retained for review."
}

$nativeVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($nativeOutput)
$testVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($testOutput)
if ($nativeVersion.FileVersion -ne '0.1.0.1' -or $testVersion.FileVersion -ne '0.1.0.1' -or
    $nativeVersion.ProductVersion -ne '0.1.0-dev-preview.1' -or
    $nativeVersion.ProductVersion -ne $testVersion.ProductVersion) {
    throw 'The compiled production/test metadata versions do not match the fixed developer-preview versions.'
}
$hashes = [ordered]@{}
foreach ($inputFile in @($nativeSource, $testSource, $assemblyMetadata, $nativeOutput, $testOutput)) {
    $hashes[[System.IO.Path]::GetFileName($inputFile)] = (Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash.ToLowerInvariant()
}
$receipt = [ordered]@{
    status = 'COMPILED_ONLY_NOT_EXECUTED_OR_SIGNED'
    compilerSha256 = (Get-FileHash -LiteralPath $compilerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    compilerFileVersion = $compilerVersion.FileVersion
    compilerSignatureVerified = $true
    assemblyFileVersion = $nativeVersion.FileVersion
    productVersion = $nativeVersion.ProductVersion
    productionTarget = 'winexe'
    pureTestTarget = 'exe'
    testsExecuted = $false
    files = $hashes
}
$receipt | ConvertTo-Json -Depth 4 |
    Out-File -LiteralPath (Join-Path $outputDirectory 'build-receipt.json') -Encoding utf8
Write-Output 'Both binaries compiled. Neither binary was executed, signed, installed, or published.'
Write-Output 'Raw build output is excluded from source publication. CI packages only the explicit developer-preview allowance.'
