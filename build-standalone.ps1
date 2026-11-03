<#
.SYNOPSIS
  Merge split <script src="*.js"> tools back into standalone single-file HTML builds.
.DESCRIPTION
  Scans each .html file in this folder for a local, non-module <script src="foo.js"></script>
  tag, inlines the referenced .js file's content in place, and writes the result to .\dist\.
  Source .html/.js files are left untouched — this only produces distributable single-file
  copies (e.g. for emailing one attachment). HTML files with no local script tag are copied
  through unchanged so dist\ always holds a complete, self-contained set.
.EXAMPLE
  .\build-standalone.ps1
#>

param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$OutDir = (Join-Path $PSScriptRoot 'dist')
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$pattern = '<script\s+src="([^"]+\.js)"\s*></script>'
$htmlFiles = Get-ChildItem -Path $SourceDir -Filter *.html -File

foreach ($file in $htmlFiles) {
    $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
    $tagMatches = [regex]::Matches($content, $pattern)

    if ($tagMatches.Count -eq 0) {
        Copy-Item -Path $file.FullName -Destination (Join-Path $OutDir $file.Name) -Force
        Write-Host "  copied as-is (no local script tag): $($file.Name)"
        continue
    }

    $merged = $content
    $mergedCount = 0
    foreach ($m in $tagMatches) {
        $jsRelPath = $m.Groups[1].Value
        if ($jsRelPath -match '^(https?:)?//') {
            continue  # external/CDN script, leave as-is
        }

        $jsPath = Join-Path $file.DirectoryName $jsRelPath
        if (-not (Test-Path $jsPath)) {
            Write-Warning "  $($file.Name): referenced '$jsRelPath' not found, leaving tag as-is"
            continue
        }

        $jsContent = Get-Content -Path $jsPath -Raw -Encoding UTF8
        $inline = "<script>`r`n$jsContent`r`n</script>"
        $merged = $merged.Replace($m.Value, $inline)
        $mergedCount++
    }

    $outPath = Join-Path $OutDir $file.Name
    Set-Content -Path $outPath -Value $merged -Encoding utf8 -NoNewline
    Write-Host "  merged $mergedCount script(s) -> $($file.Name)"
}

# The generator runs an uploaded analyzer page only when its SHA-256 is known (XN85).
# Write this build's analyzer hash into the generator so files from the same release are accepted.
$parserOut = Join-Path $OutDir 'switch-config-parser.html'
$genOut = Join-Path $OutDir 'switch-config-generator.html'
if ((Test-Path $parserOut) -and (Test-Path $genOut)) {
    $parserHash = (Get-FileHash -Path $parserOut -Algorithm SHA256).Hash.ToLower()
    $genContent = Get-Content -Path $genOut -Raw -Encoding UTF8
    if ($genContent.Contains('__PARSER_SHA256_THIS_BUILD__')) {
        $genContent = $genContent.Replace('__PARSER_SHA256_THIS_BUILD__', $parserHash)
        Set-Content -Path $genOut -Value $genContent -Encoding utf8 -NoNewline
        Write-Host "  generator: trusted analyzer SHA-256 $parserHash"
    } else {
        Write-Warning "  generator: placeholder __PARSER_SHA256_THIS_BUILD__ not found"
    }
}

Write-Host "`nDone. Standalone single-file builds are in: $OutDir"
