[CmdletBinding()]
param(
    [string]$Builder,
    [string]$CaptureTag = "aniimo-capture:m1",
    [string]$AnalyzerTag = "aniimo-analyzer:m1"
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Builder)) {
    $Builder = (docker context show).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Builder)) {
        throw "Unable to resolve the active Docker context for buildx."
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sbomRoot = Join-Path $repositoryRoot ".aitools/sbom"
New-Item -ItemType Directory -Force -Path $sbomRoot | Out-Null

docker buildx build --builder $Builder --platform linux/amd64 --load --sbom=true --provenance=mode=max `
    --file (Join-Path $repositoryRoot "docker/capture.Dockerfile") --tag $CaptureTag $repositoryRoot
if ($LASTEXITCODE -ne 0) { throw "Capture image build failed." }

docker buildx build --builder $Builder --platform linux/amd64 --load --sbom=true --provenance=mode=max `
    --file (Join-Path $repositoryRoot "docker/analyzer.Dockerfile") --tag $AnalyzerTag $repositoryRoot
if ($LASTEXITCODE -ne 0) { throw "Analyzer image build failed." }

docker scout sbom --format spdx --output (Join-Path $sbomRoot "capture.spdx.json") $CaptureTag
if ($LASTEXITCODE -ne 0) { throw "Capture SBOM generation failed." }
docker scout sbom --format spdx --output (Join-Path $sbomRoot "analyzer.spdx.json") $AnalyzerTag
if ($LASTEXITCODE -ne 0) { throw "Analyzer SBOM generation failed." }

$result = [ordered]@{
    capture_image_id = docker image inspect $CaptureTag --format '{{.Id}}'
    analyzer_image_id = docker image inspect $AnalyzerTag --format '{{.Id}}'
    capture_sbom = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $sbomRoot "capture.spdx.json")).Hash.ToLowerInvariant()
    analyzer_sbom = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $sbomRoot "analyzer.spdx.json")).Hash.ToLowerInvariant()
}
$result | ConvertTo-Json

