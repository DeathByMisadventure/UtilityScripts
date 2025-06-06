#!/bin/bash

# Usage function for help message
usage() {
    echo "Usage: $0 [helm|compose] [path/compose-file] [-i <ImageFilter>] [-s <MinSeverity>] [-d|--debug] [additional arguments]"
    echo "    helm / compose - (required) Type of input, helm chart or docker compose"
    echo "    path / compose-file - (optional)"
    echo "        if helm, the path to the chart defaults to current folder"
    echo "        if compose, the path and file name to docker-compose.yaml type file"
    echo "    -i <string> - (optional) Filter images containing this string, defaults to '' (no filter)"
    echo "        Example: -i alert-suite"
    echo "    -s <string> - (optional) Minimum vulnerability severity to include (Critical, High, Medium, Low, Negligible, Unknown), defaults to 'High'"
    echo "        Includes specified severity and higher (e.g., -s Medium includes Medium, High, Critical)"
    echo "        Example: -s Medium"
    echo "    -d, --debug - (optional) Enable debug output"
    echo "        Example: -d or --debug"
    echo "    additional arguments - (optional) Additional arguments to pass to helm or docker compose commands"
    echo "        Example for helm: --set key=value --namespace mynamespace"
    echo "        Example for compose: --project-name myproject"
    echo "Note: Use a space between parameter names and values (e.g., -i alert-suite, not -i=alert-suite)"
    exit 0
}

# Debug function to conditionally output messages
debug() {
    if [ "$DEBUG" = true ]; then
        echo "DEBUG: $*" >&2
    fi
}

# Function to format a number to two significant digits
format_significant_digits() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
        return
    fi
    # Use bc and awk to mimic PowerShell's Format-SignificantDigits
    result=$(echo "$value" | awk '
        function round(num, places) {
            factor = 10^places
            return int(num * factor + 0.5) / factor
        }
        {
            if ($1 == 0) {
                print "0.0"
                exit
            }
            abs = ($1 < 0) ? -$1 : $1
            mag = int(log(abs)/log(10))
            shift = 1 - mag
            scale = 10^shift
            rounded = round($1 * scale, 1)
            printf "%." shift "f\n", rounded
        }' | sed 's/\.0*$//;s/\.$//')
    echo "$result"
}

# Initialize debug flag
DEBUG=false

# Parse arguments
image_filter=""
min_severity="High"
source_type=""
source_path=""
additional_args=""

# Positional arguments
if [ $# -eq 0 ]; then
    usage
fi
source_type="$1"
shift
if [ $# -gt 0 ]; then
    source_path="$1"
    shift
fi

# Options
while getopts "i:s:d" opt; do
    case $opt in
        i) image_filter="$OPTARG" ;;
        s) min_severity="$OPTARG" ;;
        d) DEBUG=true ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
    esac
done
shift $((OPTIND-1))

# Handle long option --debug
while [ $# -gt 0 ]; do
    if [ "$1" = "--debug" ]; then
        DEBUG=true
        shift
    else
        additional_args="$additional_args $1"
        shift
    fi
done
additional_args=${additional_args# }

# Validate SourceType
source_type=$(echo "$source_type" | tr -d '[:space:]')
if [ "$source_type" != "helm" ] && [ "$source_type" != "compose" ]; then
    echo "Error: SourceType must be 'helm' or 'compose'." >&2
    exit 1
fi

# Debug logging
debug "SourceType: '$source_type'"
debug "SourcePath: '$source_path'"
debug "ImageFilter: '$image_filter'"
debug "MinSeverity: '$min_severity'"
debug "AdditionalArgs: '$additional_args'"

# Set default SourcePath
if [ -z "$source_path" ]; then
    if [ "$source_type" = "helm" ]; then
        source_path="."
    else
        source_path="docker-compose.yaml"
    fi
fi

# Normalize SourcePath (replace leading backslash with ./)
source_path=$(echo "$source_path" | sed 's|^\\|./|')

# Create log file
log_file="grype-scan-error-$(date +%Y%m%d-%H%M%S).log"
debug "Logging errors to $log_file"

# Check prerequisites
if ! command -v helm >/dev/null 2>&1; then
    echo "Error: helm is not installed." >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed." >&2
    exit 1
fi
if [ "$source_type" = "compose" ] && ! command -v docker-compose >/dev/null 2>&1; then
    echo "Error: docker-compose is not installed. Required for 'compose' source type." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is not installed. Install it using 'sudo apt-get install jq' or equivalent." >&2
    exit 1
fi
if ! command -v bc >/dev/null 2>&1; then
    echo "Error: bc is not installed. Install it using 'sudo apt-get install bc' or equivalent." >&2
    exit 1
fi

# Validate SourcePath
if [ "$source_type" = "helm" ]; then
    if [ ! -d "$source_path" ]; then
        echo "Error: Helm chart path '$source_path' does not exist or is not a directory." >&2
        exit 1
    fi
else
    if [ ! -f "$source_path" ]; then
        echo "Error: Docker Compose file '$source_path' does not exist." >&2
        exit 1
    fi
fi

# Validate MinSeverity
valid_severities=("Critical" "High" "Medium" "Low" "Negligible" "Unknown")
min_severity_valid=false
for sev in "${valid_severities[@]}"; do
    if [ "${min_severity,,}" = "${sev,,}" ]; then
        min_severity_valid=true
        break
    fi
done
if [ "$min_severity_valid" = false ]; then
    echo "Error: Invalid MinSeverity '$min_severity'. Must be one of: ${valid_severities[*]}." >&2
    exit 1
fi

# Generate dynamic CSV file name based on current date
date_str=$(date +%m-%d-%Y)
csv_file="grype-$date_str.csv"

# Initialize results array (will append to CSV directly)
echo '"Image","Package","VersionInstalled","FixedIn","Type","VulnerabilityID","Severity","EPSS","Risk","Source"' > "$csv_file"

# Define severity hierarchy
declare -A severity_priority=(
    ["Critical"]=4
    ["High"]=3
    ["Medium"]=2
    ["Low"]=1
    ["Unknown"]=0.5
    ["Negligible"]=0
)

# Get severities to include based on MinSeverity
min_priority=${severity_priority["$min_severity"]}
severities_to_include=""
for sev in "${!severity_priority[@]}"; do
    sev_priority=${severity_priority["$sev"]}
    if [ -n "$sev_priority" ] && [ -n "$min_priority" ] && [ $(echo "$sev_priority >= $min_priority" | bc -l) -eq 1 ]; then
        severities_to_include="$severities_to_include,$sev"
    fi
done
# Remove leading comma
severities_to_include=${severities_to_include#,}

# Get unique images from specified source
if [ "$source_type" = "helm" ]; then
    helm_command="helm template test $source_path $additional_args"
    debug "Executing: $helm_command"
    images=$(eval "$helm_command" | grep 'image:' | sed -E 's/^\s*image:\s*//;s/\s*$//' | sort -u)
else
    compose_command="docker compose -f $source_path config $additional_args --format yaml"
    debug "Executing: $compose_command"
    images=$(eval "$compose_command" | grep 'image:' | sed -E 's/^\s*image:\s*//;s/\s*$//' | sort -u)
fi

# Apply ImageFilter if provided
if [ -n "$image_filter" ]; then
    images=$(echo "$images" | grep -E "$image_filter")
fi

if [ -z "$images" ]; then
    echo "Error: No images found in $source_type output${image_filter:+ with filter '$image_filter'}." >&2
    exit 1
fi

# Process each image
while IFS= read -r image; do
    [ -z "$image" ] && continue
    echo "Scanning image: $image"
    # Strip the part of image up to and including the first /
    stripped_image=$(echo "$image" | sed 's|^[^/]+/||')

    # Validate image name (basic check)
    if ! echo "$image" | grep -E '^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[a-zA-Z0-9._-]+)?$' >/dev/null; then
        echo "Error: Invalid image name format: $image" >&2
        echo "Invalid image name format: $image" >> "$log_file"
        echo "\"$stripped_image\",\"\",\"\",\"\",\"\",\"\",\"Error: Invalid image name format\",\"\",\"\",\"ironbank\"" >> "$csv_file"
        continue
    fi

    # Check if image is accessible
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "Warning: Image $image not found locally. Attempting to pull..." >&2
        if ! docker pull "$image" >/dev/null 2>&1; then
            echo "Error: Failed to pull image $image. Check registry authentication or image name." >&2
            echo "Tip: Run 'docker login nexus-registry.project1.kbstar-st.com' if authentication is required." >&2
            echo "Failed to pull image: $image" >> "$log_file"
            echo "\"$stripped_image\",\"\",\"\",\"\",\"\",\"\",\"Error: Failed to pull image\",\"\",\"\",\"ironbank\"" >> "$csv_file"
            continue
        fi
    fi

    # Run grype with JSON output
    scan_output_raw=$(docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest \
        --sort-by severity --output json --quiet "$image" 2>&1)
    if ! echo "$scan_output_raw" | jq . >/dev/null 2>&1; then
        echo "Error processing JSON for $image: Invalid JSON output" >&2
        echo "Invalid JSON output for image: $image\nRaw output:\n$scan_output_raw" >> "$log_file"
        echo "Raw output logged to $log_file" >&2
        echo "\"$stripped_image\",\"\",\"\",\"\",\"\",\"\",\"Error processing scan output\",\"\",\"\",\"ironbank\"" >> "$csv_file"
        continue
    fi

    # Filter for vulnerabilities at or above MinSeverity
    if [ -n "$severities_to_include" ]; then
        scan_matches=$(echo "$scan_output_raw" | jq -c ".matches[] | select(.vulnerability.severity | IN(\"${severities_to_include//,/\",\"}\"))")
    else
        scan_matches=""
    fi

    if [ -n "$scan_matches" ]; then
        while IFS= read -r match; do
            # Extract fields
            package=$(echo "$match" | jq -r '.artifact.name // ""')
            version_installed=$(echo "$match" | jq -r '.artifact.version // ""')
            fixed_in=$(echo "$match" | jq -r 'if .vulnerability.fix.versions then .vulnerability.fix.versions | join(",") else "" end')
            type=$(echo "$match" | jq -r '.artifact.type // ""')
            vulnerability_id=$(echo "$match" | jq -r '.vulnerability.id // ""')
            severity=$(echo "$match" | jq -r '.vulnerability.severity // ""')
            epss_value=$(echo "$match" | jq -r '.vulnerability.epss[0].epss // ""')
            risk_value=$(echo "$match" | jq -r '.vulnerability.risk // ""')

            # Format EPSS and Risk
            epss_formatted=$(format_significant_digits "$epss_value")
            risk_formatted=$(format_significant_digits "$risk_value")

            # Determine source based on Type
            source_value="ironbank"
            if [ "${type,,}" = "java-archive" ]; then
                source_value="framework"
            fi

            # Escape quotes in fields for CSV
            package=$(echo "$package" | sed 's/"/""/g')
            version_installed=$(echo "$version_installed" | sed 's/"/""/g')
            fixed_in=$(echo "$fixed_in" | sed 's/"/""/g')
            type=$(echo "$type" | sed 's/"/""/g')
            vulnerability_id=$(echo "$vulnerability_id" | sed 's/"/""/g')
            severity=$(echo "$severity" | sed 's/"/""/g')
            epss_formatted=$(echo "$epss_formatted" | sed 's/"/""/g')
            risk_formatted=$(echo "$risk_formatted" | sed 's/"/""/g')
            source_value=$(echo "$source_value" | sed 's/"/""/g')

            echo "\"$stripped_image\",\"$package\",\"$version_installed\",\"$fixed_in\",\"$type\",\"$vulnerability_id\",\"$severity\",\"$epss_formatted\",\"$risk_formatted\",\"$source_value\"" >> "$csv_file"
        done <<< "$scan_matches"
    else
        echo "No vulnerabilities found for $image with severity $min_severity or higher." >&2
        echo "\"$stripped_image\",\"\",\"\",\"\",\"\",\"\",\"No vulnerabilities found with severity $min_severity or higher\",\"\",\"\",\"ironbank\"" >> "$csv_file"
    fi
done <<< "$images"

if [ -s "$csv_file" ]; then
    echo "Processing complete. CSV saved to $csv_file."
else
    echo "No results to export." >&2
    rm -f "$csv_file"
fi
