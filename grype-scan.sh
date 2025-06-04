#!/bin/bash

# Usage function
usage() {
    echo "Usage: $0 [helm|compose] [path/compose-file] [--image-filter <string>] [--min-severity <string>]"
    echo "    helm|compose - (required) Type of input, helm chart or docker compose"
    echo "    path/compose-file - (optional)"
    echo "        if helm, path to chart, defaults to current folder"
    echo "        if compose, path to docker-compose.yaml type file, defaults to 'docker-compose.yaml'"
    echo "    --image-filter <string> - (optional) Filter images containing this string, defaults to '' (no filter)"
    echo "        Example: --image-filter alert-suite"
    echo "    --min-severity <string> - (optional) Minimum vulnerability severity (Critical, High, Medium, Low, Negligible, Unknown), defaults to 'High'"
    echo "        Includes specified severity and higher (e.g., --min-severity Medium includes Medium, High, Critical)"
    echo "        Example: --min-severity Medium"
    echo "Note: Use space between option names and values (e.g., --image-filter alert-suite, not --image-filter=alert-suite)"
    exit 0
}

# Function to format number to two significant digits
format_significant_digits() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
        return
    fi
    if [ "$value" = "0" ]; then
        echo "0.0"
        return
    fi
    # Use awk to compute two significant digits
    echo "$value" | awk '{
        if ($1 == 0) { print "0.0"; next }
        abs = ($1 < 0 ? -$1 : $1)
        mag = int(log(abs)/log(10))
        shift = 1 - mag
        scale = 10^shift
        rounded = sprintf("%.1f", $1 * scale)
        printf("%." shift "f\n", rounded)
    }' | sed 's/\.0*$//'
}

# Initialize log file variable
log_file=""

# Function to log errors
log_error() {
    local message="$1"
    if [ -z "$log_file" ]; then
        log_file="grype-scan-error-$(date +%Y%m%d-%H%M%S).log"
        echo "Error log created at $log_file" >&2
    fi
    echo "$message" >> "$log_file"
}

# Parse arguments
source_type=""
source_path=""
image_filter=""
min_severity="High"

while [[ $# -gt 0 ]]; do
    case "$1" in
        helm|compose)
            source_type="$1"
            shift
            ;;
        --image-filter)
            image_filter="$2"
            shift 2
            ;;
        --min-severity)
            min_severity="$2"
            shift 2
            ;;
        *)
            if [ -z "$source_path" ]; then
                source_path="$1"
                shift
            else
                echo "Error: Unexpected argument '$1'"
                usage
            fi
            ;;
    esac
done

# Validate source_type
if [ -z "$source_type" ]; then
    usage
fi

# Set default source_path
if [ -z "$source_path" ]; then
    if [ "$source_type" = "helm" ]; then
        source_path="."
    else
        source_path="docker-compose.yaml"
    fi
fi

# Normalize source_path (replace leading \ with ./)
source_path="${source_path#\\}"
if [[ "$source_path" != /* && "$source_path" != ./* ]]; then
    source_path="./$source_path"
fi

# Check prerequisites
if ! command -v helm >/dev/null; then
    echo "Error: helm is not installed." >&2
    exit 1
fi
if ! command -v docker >/dev/null; then
    echo "Error: docker is not installed." >&2
    exit 1
fi
if [ "$source_type" = "compose" ] && ! command -v docker-compose >/dev/null; then
    echo "Error: docker-compose is not installed. Required for 'compose' source type." >&2
    exit 1
fi
if ! command -v jq >/dev/null; then
    echo "Error: jq is not installed. Install it using your package manager (e.g., 'apt install jq' or 'brew install jq')." >&2
    exit 1
fi

# Validate source_path
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

# Generate CSV file name
month=$(date +%B | tr '[:upper:]' '[:lower:]')
year=$(date +%Y)
csv_file="grype-$month-$year.csv"

# Initialize CSV
echo "Image,Package,VersionInstalled,FixedIn,Type,VulnerabilityID,Severity,EPSS,Risk" > "$csv_file"

# Define severity hierarchy
declare -A severity_priority=(
    ["Critical"]=4
    ["High"]=3
    ["Medium"]=2
    ["Low"]=1
    ["Unknown"]=0.5
    ["Negligible"]=0
)

# Validate min_severity
if [[ ! ${severity_priority[$min_severity]} ]]; then
    echo "Error: Invalid --min-severity '$min_severity'. Must be one of: Critical, High, Medium, Low, Negligible, Unknown" >&2
    exit 1
fi

# Get severities to include
min_priority="${severity_priority[$min_severity]}"
severities_to_include=""
for severity in "${!severity_priority[@]}"; do
    priority="${severity_priority[$severity]}"
    if [ "$(echo "$priority >= $min_priority" | bc -l)" -eq 1 ]; then
        severities_to_include="$severities_to_include $severity"
    fi
done

# Get unique images
if [ "$source_type" = "helm" ]; then
    images=$(helm template test "$source_path" | grep 'image:' | sed -E 's/^\s*image:\s*//; s/\s*$//' | sort -u)
else
    images=$(docker compose -f "$source_path" config --format yaml | grep 'image:' | sed -E 's/^\s*image:\s*//; s/\s*$//' | sort -u)
fi

if [ -n "$image_filter" ]; then
    images=$(echo "$images" | grep -E "$image_filter")
fi

if [ -z "$images" ]; then
    echo "Error: No images found in $source_type output${image_filter:+ with filter '$image_filter'}" >&2
    exit 1
fi

# Process each image
while IFS= read -r image; do
    echo "Scanning image: $image"
    stripped_image="${image##*/}"

    # Validate image name
    if ! echo "$image" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[a-zA-Z0-9._-]+)?$'; then
        echo "Error: Invalid image name format: $image" >&2
        log_error "Invalid image name format: $image"
        printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
            "$stripped_image" "" "" "" "" "" "Error: Invalid image name format" "" "" >> "$csv_file"
        continue
    fi

    # Check if image exists
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "Warning: Image $image not found locally. Attempting to pull..." >&2
        if ! docker pull "$image" >/dev/null 2>&1; then
            echo "Error: Failed to pull image $image. Check registry authentication or image name." >&2
            echo "Tip: Run 'docker login <registry>' if authentication is required." >&2
            log_error "Failed to pull image: $image"
            printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
                "$stripped_image" "" "" "" "" "" "Error: Failed to pull image" "" "" >> "$csv_file"
            continue
        fi
    fi

    # Run grype scan
    scan_output=$(docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock --name Grype anchore/grype:v0.92.2 \
        --sort-by severity --output json --quiet "$image" 2>&1)
    if [ $? -ne 0 ] || ! echo "$scan_output" | jq -e . >/dev/null 2>&1; then
        echo "Error processing JSON for $image: Invalid JSON output" >&2
        log_error "Invalid JSON output for image: $image"
        log_error "Raw output:"
        log_error "$scan_output"
        printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
            "$stripped_image" "" "" "" "" "" "Error processing scan output" "" "" >> "$csv_file"
        continue
    fi

    # Filter matches by severity
    matches=$(echo "$scan_output" | jq -c '.matches[] | select(.vulnerability.severity | IN("'"${severities_to_include// /\",\"}"'"))')
    if [ -n "$matches" ]; then
        while IFS= read -r match; do
            package=$(echo "$match" | jq -r '.artifact.name // ""')
            version=$(echo "$match" | jq -r '.artifact.version // ""')
            fixed_in=$(echo "$match" | jq -r '.vulnerability.fix.versions // empty | join(",")')
            type=$(echo "$match" | jq -r '.artifact.type // ""')
            vuln_id=$(echo "$match" | jq -r '.vulnerability.id // ""')
            severity=$(echo "$match" | jq -r '.vulnerability.severity // ""')
            epss=$(echo "$match" | jq -r '.vulnerability.epss[0].epss // ""')
            risk=$(echo "$match" | jq -r '.vulnerability.risk // ""')

            epss_formatted=$(format_significant_digits "$epss")
            risk_formatted=$(format_significant_digits "$risk")

            # Escape CSV fields
            package=$(echo "$package" | sed 's/"/""/g')
            version=$(echo "$version" | sed 's/"/""/g')
            fixed_in=$(echo "$fixed_in" | sed 's/"/""/g')
            type=$(echo "$type" | sed 's/"/""/g')
            vuln_id=$(echo "$vuln_id" | sed 's/"/""/g')
            severity=$(echo "$severity" | sed 's/"/""/g')
            stripped_image=$(echo "$stripped_image" | sed 's/"/""/g')

            printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
                "$stripped_image" "$package" "$version" "$fixed_in" "$type" "$vuln_id" "$severity" "$epss_formatted" "$risk_formatted" >> "$csv_file"
        done <<< "$matches"
    else
        echo "No vulnerabilities found for $image with severity $min_severity or higher."
        printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
            "$stripped_image" "" "" "" "" "" "No vulnerabilities found with severity $min_severity or higher" "" "" >> "$csv_file"
    fi
done <<< "$images"

echo "Processing complete. CSV saved to $csv_file"
