#!/bin/bash
# Packages images from a Helm chart and the chart itself into an images directory
# Usage: ./package-images.sh [chart_path] [optional_values_file]
# To restore images: for FILE in images/*.tar.gz; do docker load < "$FILE"; done

# Exit on any error
set -e

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Error handling function
error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
    exit 1
}

# Validate prerequisites
command -v helm >/dev/null 2>&1 || error "Helm is required but not installed"
command -v docker >/dev/null 2>&1 || error "Docker is required but not installed"
command -v awk >/dev/null 2>&1 || error "awk is required but not installed"

# Set chart path (default to ./charts if not provided)
chart_path="${1:-./charts}"
values_file="$2"

# Validate chart path
[ -d "$chart_path" ] || error "Chart path '$chart_path' does not exist"
[ -f "$chart_path/Chart.yaml" ] || error "No Chart.yaml found in '$chart_path'"

# Validate values file if provided
if [ -n "$values_file" ]; then
    [ -f "$values_file" ] || error "Values file '$values_file' does not exist"
fi

# Create images directory
mkdir -p images || error "Failed to create images directory"

# Get chart name from Chart.yaml
get_chart_name() {
    if command -v yq >/dev/null 2>&1; then
        yq e '.name' "$chart_path/Chart.yaml" 2>/dev/null
    else
        grep '^name:' "$chart_path/Chart.yaml" | awk '{print $2}' | tr -d '\r' 2>/dev/null
    fi
}

chart_name=$(get_chart_name)
# Fallback to basename if chart name parsing fails
[ -z "$chart_name" ] && chart_name=$(basename "$chart_path")

# Get unique images from helm template
log "Extracting images from Helm chart at $chart_path"
helm_template_cmd="helm template test \"$chart_path\""
[ -n "$values_file" ] && helm_template_cmd="$helm_template_cmd -f \"$values_file\""

images=$(eval "$helm_template_cmd" 2>/dev/null |
    awk '/image:/ { gsub(/.*image: /, ""); gsub(/\r/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); print }' |
    sort -u) || error "Failed to extract images from Helm template"

# Process images sequentially
while read -r image; do
    [ -z "$image" ] && continue
    file="${image##*/}"
    output="images/${file//:/_}.tar.gz"

    log "Processing $image to $output"

    if docker pull "$image" 2>/dev/null; then
        if docker save "$image" | gzip > "$output"; then
            log "Successfully saved $image to $output"
        else
            error "Failed to save $image"
        fi
    else
        error "Failed to pull $image"
    fi
done <<< "$images"

# Package the Helm chart
log "Packaging Helm chart $chart_name"
if helm package "$chart_path" --destination images/ >/dev/null; then
    log "Helm chart packaged and saved to images/${chart_name}-*.tgz"
else
    error "Failed to package Helm chart"
fi

log "Processing complete. Images and chart saved in images/"
