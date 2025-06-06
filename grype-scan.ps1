    <#
        .SYNOPSIS
        Analyzes helm charts and docker compose files for images to scan with Grype

        .DESCRIPTION
        Analyzes helm charts and docker compose files for images to scan with Grype for
        vulnerabilities.

        .PARAMETER SourceType
        Either "helm" or "compose"

        .PARAMETER SourcePath
        If helm, the path to the chart
        If docker compose, the path to the docker-compose.yaml file

        .PARAMETER ImageFilter
        (Optional) A filter for image names to only process those that match

        .PARAMETER MinSeverity
        (Optional)(Default: High) The minimum severity to report on

        .LINK
        Online version: https://github.com/DeathByMisadventure/UtilityScripts
    #>
# Command-line arguments
param (
    [Parameter(Position = 0)]
    [ValidateSet("helm", "compose")]
    [AllowEmptyString()]
    [string]$SourceType = "",
    [Parameter(Position = 1)]
    [AllowEmptyString()]
    [string]$SourcePath = "",
    [Parameter()]
    [AllowEmptyString()]
    [string]$ImageFilter = "",
    [Parameter()]
    [ValidateSet("Critical", "High", "Medium", "Low", "Negligible", "Unknown")]
    [string]$MinSeverity = "High",
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$RemainingArgs = @()
)

# Function to format a number to two significant digits
function Format-SignificantDigits {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Value
    )
    if ([string]::IsNullOrEmpty($Value)) {
        return ""
    }
    try {
        $num = [double]$Value
        if ($num -eq 0) {
            return "0.0"
        }
        $absValue = [math]::Abs($num)
        $magnitude = [math]::Floor([math]::Log10($absValue))
        $shift = 1 - $magnitude
        $scale = [math]::Pow(10, $shift)
        $rounded = [math]::Round($num * $scale, 1)
        $formatted = "{0:F$shift}" -f $rounded
        return $formatted.TrimEnd('0').TrimEnd('.')
    }
    catch {
        return ""
    }
}

# Capture additional arguments
$additionalArgs = $RemainingArgs

# Display help message if no arguments provided
if ([string]::IsNullOrEmpty($SourceType)) {
    Write-Host "Usage: grype-chart-scan.ps1 [helm / compose] [path / compose-file] [-ImageFilter <string>] [-MinSeverity <string>] [additional arguments]"
    Write-Host "    helm / compose - (required) Type of input, helm chart or docker compose"
    Write-Host "    path / compose-file - (optional)"
    Write-Host "        if helm, the path to the chart defaults current folder"
    Write-Host "        if compose, the path and file name to docker-compose.yaml type file"
    Write-Host "    -ImageFilter <string> - (optional) Filter images containing this string, defaults to '' (no filter)"
    Write-Host "        Example: -ImageFilter alert-suite"
    Write-Host "    -MinSeverity <string> - (optional) Minimum vulnerability severity to include (Critical, High, Medium, Low, Negligible, Unknown), defaults to 'High'"
    Write-Host "        Includes specified severity and higher (e.g., -MinSeverity Medium includes Medium, High, Critical)"
    Write-Host "        Example: -MinSeverity Medium"
    Write-Host "    additional arguments - (optional) Additional arguments to pass to helm or docker compose commands"
    Write-Host "        Example for helm: --set key=value --namespace mynamespace"
    Write-Host "        Example for compose: --project-name myproject"
    Write-Host "Note: Use a space between parameter names and values (e.g., -ImageFilter alert-suite, not -ImageFilter=alert-suite)"
    exit 0
}

# Trim SourceType to avoid whitespace issues
$SourceType = $SourceType.Trim()

# Debug: Log arguments for troubleshooting
Write-Debug "SourceType: '$SourceType'"
Write-Debug "SourcePath: '$SourcePath'"
Write-Debug "ImageFilter: '$ImageFilter'"
Write-Debug "MinSeverity: '$MinSeverity'"
Write-Debug "AdditionalArgs: '$additionalArgs'"

# Set default SourcePath based on SourceType
if (-not $SourcePath) {
    if ($SourceType -eq "helm") {
        $SourcePath = "."
    }
    else {
        $SourcePath = "docker-compose.yaml"
    }
}

# Normalize SourcePath (handle leading backslash)
$SourcePath = $SourcePath -replace '^\\', '.\'

# Create log file for debugging
$logFile = "grype-scan-error-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Write-Debug "Logging errors to $logFile"

# Check prerequisites
if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
    Write-Error "Error: helm is not installed."
    exit 1
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Error: docker is not installed."
    exit 1
}
if ($SourceType -eq "compose" -and -not (Get-Command "docker-compose" -ErrorAction SilentlyContinue)) {
    Write-Error "Error: docker-compose is not installed. Required for 'compose' source type."
    exit 1
}
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Error "Error: ImportExcel module is not installed. Run 'Install-Module -Name ImportExcel -Scope CurrentUser'."
    exit 1
}

# Validate SourcePath
if ($SourceType -eq "helm") {
    if (-not (Test-Path $SourcePath -PathType Container)) {
        Write-Error "Error: Helm chart path '$SourcePath' does not exist or is not a directory."
        exit 1
    }
}
else {
    if (-not (Test-Path $SourcePath -PathType Leaf)) {
        Write-Error "Error: Docker Compose file '$SourcePath' does not exist."
        exit 1
    }
}

# Generate dynamic XLSX file name based on current date
$date = Get-Date -Format "MM-dd-yyyy"
$xlsxFile = "grype-$date.xlsx"

# Initialize results array
$results = @()

# Define severity hierarchy
$severityPriority = @{
    "Critical"   = 4
    "High"       = 3
    "Medium"     = 2
    "Low"        = 1
    "Unknown"    = 0.5
    "Negligible" = 0
}

# Get severities to include based on MinSeverity
$minPriority = $severityPriority[$MinSeverity]
$severitiesToInclude = $severityPriority.Keys | Where-Object { $severityPriority[$_] -ge $minPriority }

# Get unique images from specified source, applying filter if provided
if ($SourceType -eq "helm") {
    $helmCommand = "helm template test $SourcePath $additionalArgs"
    Write-Debug "Executing: $helmCommand"
    $images = Invoke-Expression $helmCommand | Select-String 'image:' |
    ForEach-Object { $_ -replace '^\s*image:\s*', '' -replace '\s*$', '' }
    if (-not [string]::IsNullOrEmpty($ImageFilter)) {
        $images = $images | Where-Object { $_ -match [regex]::Escape($ImageFilter) }
    }
    $images = $images | Sort-Object -Unique
}
else {
    $composeCommand = "docker compose -f $SourcePath config $additionalArgs --format yaml"
    Write-Debug "Executing: $composeCommand"
    $images = Invoke-Expression $composeCommand | Select-String 'image:' |
    ForEach-Object { $_ -replace '^\s*image:\s*', '' -replace '\s*$', '' }
    if (-not [string]::IsNullOrEmpty($ImageFilter)) {
        $images = $images | Where-Object { $_ -match [regex]::Escape($ImageFilter) }
    }
    $images = $images | Sort-Object -Unique
}

if (-not $images) {
    Write-Error "Error: No images found in $SourceType output$(if ($ImageFilter) { " with filter '$ImageFilter'" })."
    exit 1
}

foreach ($image in $images) {
    Write-Host "Scanning image: $image"
    # Strip the part of image up to and including the first /
    $strippedImage = $image -replace '^[^/]+/', ''

    # Validate image name (basic check for valid Docker image reference)
    if ($image -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[a-zA-Z0-9._-]+)?$') {
        Write-Host "Error: Invalid image name format: $image"
        "Invalid image name format: $image" | Out-File -FilePath $logFile -Append
        $results += [PSCustomObject]@{
            Image            = $strippedImage
            Package          = ""
            VersionInstalled = ""
            FixedIn          = ""
            Type             = ""
            VulnerabilityID  = ""
            Severity         = "Error: Invalid image name format"
            EPSS             = ""
            Risk             = ""
            Source           = "ironbank"
        }
        continue
    }

    # Check if image is accessible
    $imageExists = docker image inspect $image 2>$null
    if (-not $imageExists) {
        Write-Host "Warning: Image $image not found locally. Attempting to pull..."
        try {
            docker pull $image | Out-Null
        }
        catch {
            Write-Host "Error: Failed to pull image $image. Check registry authentication or image name."
            Write-Host "Tip: Run 'docker login nexus-registry.project1.kbstar-st.com' if authentication is required."
            $errorDetails = "Failed to pull image: $image`n$($_.Exception.Message)"
            $errorDetails | Out-File -FilePath $logFile -Append
            $results += [PSCustomObject]@{
                Image            = $strippedImage
                Package          = ""
                VersionInstalled = ""
                FixedIn          = ""
                Type             = ""
                VulnerabilityID  = ""
                Severity         = "Error: Failed to pull image"
                EPSS             = ""
                Risk             = ""
                Source           = "ironbank"
            }
            continue
        }
    }

    # Run grype with JSON output, capturing stderr separately, without specifying a container name
    try {
        $scanOutputRaw = docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest `
            --sort-by severity --output json --quiet $image 2>&1
        $scanOutput = $scanOutputRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "Error processing JSON for ${image}: Invalid JSON output"
        $errorDetails = "Invalid JSON output for image: $image`nRaw output:`n$scanOutputRaw`nError: $($_.Exception.Message)"
        $errorDetails | Out-File -FilePath $logFile -Append
        Write-Host "Raw output logged to $logFile"
        $results += [PSCustomObject]@{
            Image            = $strippedImage
            Package          = ""
            VersionInstalled = ""
            FixedIn          = ""
            Type             = ""
            VulnerabilityID  = ""
            Severity         = "Error processing scan output"
            EPSS             = ""
            Risk             = ""
            Source           = "ironbank"
        }
        continue
    }

    # Filter for vulnerabilities at or above MinSeverity
    $scanMatches = $scanOutput.matches | Where-Object { $_.vulnerability.severity -in $severitiesToInclude }

    if ($scanMatches) {
        foreach ($match in $scanMatches) {
            # Handle EPSS value
            $epssValue = ""
            if ($match.vulnerability.epss -and $match.vulnerability.epss.Count -gt 0 -and $null -ne $match.vulnerability.epss[0].epss) {
                $epssValue = $match.vulnerability.epss[0].epss
            }

            # Handle Risk value
            $riskValue = ""
            if ($null -ne $match.vulnerability.risk) {
                $riskValue = $match.vulnerability.risk
            }

            # Determine Source based on Type
            $artifactType = if ($null -ne $match.artifact.type) { $match.artifact.type } else { "" }
            $sourceValue = if ($artifactType.ToLower() -eq "java-archive") { "framework" } else { "ironbank" }

            $results += [PSCustomObject]@{
                Image            = $strippedImage
                Package          = if ($null -ne $match.artifact.name) { $match.artifact.name } else { "" }
                VersionInstalled = if ($null -ne $match.artifact.version) { $match.artifact.version } else { "" }
                FixedIn          = if ($match.vulnerability.fix.versions) { $match.vulnerability.fix.versions -join "," } else { "" }
                Type             = $artifactType
                VulnerabilityID  = if ($null -ne $match.vulnerability.id) { $match.vulnerability.id } else { "" }
                Severity         = if ($null -ne $match.vulnerability.severity) { "$($match.vulnerability.severity)" } else { "" }
                EPSS             = Format-SignificantDigits $epssValue
                Risk             = Format-SignificantDigits $riskValue
                Source           = $sourceValue
            }
        }
    }
    else {
        Write-Host "No vulnerabilities found for $image with severity $MinSeverity or higher."
        $results += [PSCustomObject]@{
            Image            = $strippedImage
            Package          = ""
            VersionInstalled = ""
            FixedIn          = ""
            Type             = ""
            VulnerabilityID  = ""
            Severity         = "No vulnerabilities found with severity $MinSeverity or higher"
            EPSS             = ""
            Risk             = ""
            Source           = "ironbank"
        }
    }
}

# Export results to XLSX with conditional formatting, AutoFilter, and text format for Severity
if ($results) {
    $conditionalFormats = @(
        # Severity formatting for column G (entire row)
        New-ConditionalText -ConditionalType Equal -Text "Critical" -ConditionalTextColor Black -BackgroundColor Red -Range "G1:G1048576"
        New-ConditionalText -ConditionalType Equal -Text "High" -ConditionalTextColor Black -BackgroundColor Orange -Range "G1:G1048576"
        New-ConditionalText -ConditionalType Equal -Text "Medium" -ConditionalTextColor Black -BackgroundColor Yellow -Range "G1:G1048576"
        New-ConditionalText -ConditionalType Equal -Text "Low" -ConditionalTextColor Black -BackgroundColor LightGreen -Range "G1:G1048576"
        New-ConditionalText -ConditionalType Equal -Text "Negligible" -ConditionalTextColor Black -BackgroundColor LightGray -Range "G1:G1048576"
        New-ConditionalText -ConditionalType Equal -Text "Unknown" -ConditionalTextColor Black -BackgroundColor LightGray -Range "G1:G1048576"
        New-ConditionalText -ConditionalType ContainsText -Text "Error" -ConditionalTextColor Black -BackgroundColor Purple -Range "G1:G1048576"
        # Formatting for column J (individual cells)
        New-ConditionalText -ConditionalType Equal -Text "ironbank" -ConditionalTextColor Black -BackgroundColor LightBlue -Range "J1:J1048576"
        New-ConditionalText -ConditionalType Equal -Text "framework" -ConditionalTextColor Black -BackgroundColor LightGreen -Range "J1:J1048576"
    )
    $excelPackage = $results | Export-Excel -Path $xlsxFile -WorksheetName "Vulnerabilities" -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -ConditionalText $conditionalFormats -PassThru
    $worksheet = $excelPackage.Workbook.Worksheets["Vulnerabilities"]
    $worksheet.Cells["A:I"].Style.Numberformat.Format = "@"
    Close-ExcelPackage $excelPackage
    Write-Host "Processing complete. XLSX saved to $xlsxFile with conditional formatting applied for Severity (column G, text format) and Source (column J, populated based on Type). AutoFilter enabled on header row. Note: Severity values are prefixed with '' to avoid conflicts."
}
else {
    Write-Host "No results to export."
}
