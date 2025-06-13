#!/bin/bash

# Ultra Simple CSV Generator - Avoids complex grep operations
# Maximum compatibility with all systems

set -e

usage() {
    echo "Usage: $0 <repo_list_file> <output_file>"
    echo ""
    echo "Repo list file format (one per line):"
    echo "  cgr.dev/chainguard-private/airflow:latest"
    echo "  cgr.dev/chainguard-private/nginx:stable"
    echo ""
    exit 1
}

# Check auth
if ! chainctl auth token >/dev/null 2>&1; then
    echo "Error: chainctl authentication required" >&2
    exit 1
fi

# Parse arguments
repo_file="$1"
output_file="$2"

if [[ -z "$repo_file" || ! -f "$repo_file" ]] || [[ -z "$output_file" ]]; then
    usage
fi

# Default dates
from_date="2025-05-01T00:00:00Z"
to_date="2025-06-11T00:00:00Z"

# Try to get dynamic dates if possible
if date --version >/dev/null 2>&1; then
    from_date=$(date -d '30 days ago' -Iseconds 2>/dev/null | sed 's/+00:00/Z/' || echo "2025-05-01T00:00:00Z")
    to_date=$(date -Iseconds 2>/dev/null | sed 's/+00:00/Z/' || echo "2025-06-11T00:00:00Z")
elif date -v-30d >/dev/null 2>&1; then
    from_date=$(date -v-30d -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "2025-05-01T00:00:00Z")
    to_date=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "2025-06-11T00:00:00Z")
fi

echo "Processing repositories..." >&2
echo "Date range: $from_date to $to_date" >&2

# Initialize output file with header
echo "Repository,Tag,Date,Critical_Count,Critical_IDs,High_Count,High_IDs,Medium_Count,Medium_IDs,Low_Count,Low_IDs,Total_Count" > "$output_file"

# Create temp files for summary data
temp_dir=$(mktemp -d)
summary_file="$temp_dir/summary.txt"

# Initialize counters
total_repos=0
processed_repos=0

# Process each repository
while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
    total_repos=$((total_repos + 1))
    
    # Parse repo:tag
    if [[ "$line" =~ ^([^:]+):(.+)$ ]]; then
        repo="${BASH_REMATCH[1]}"
        tag="${BASH_REMATCH[2]}"
        
        echo "[$total_repos] Processing $repo:$tag..." >&2
        
        # Get CVE data
        cve_data=$(curl -s -H "Authorization: Bearer $(chainctl auth token)" \
            -d "repo=$repo" \
            -d "tag=$tag" \
            -d "from=$from_date" \
            -d "to=$to_date" \
            "https://console-api.enforce.dev/registry/v1/vuln_reports/counts" 2>/dev/null)
        
        if [[ -n "$cve_data" && "$cve_data" != "null" && "$cve_data" != "{}" ]]; then
            # Process the data and append to CSV
            echo "$cve_data" | jq -r --arg repo "$repo" --arg tag "$tag" '
            if .items and (.items | length > 0) then
                (.items | group_by(.date) | map({
                    date: .[0].date,
                    critical_ids: ([.[].critCveIds[]? // empty] | map(select(. != "" and . != null)) | unique),
                    high_ids: ([.[].highCveIds[]? // empty] | map(select(. != "" and . != null)) | unique),
                    medium_ids: ([.[].medCveIds[]? // empty] | map(select(. != "" and . != null)) | unique),
                    low_ids: ([.[].lowCveIds[]? // empty] | map(select(. != "" and . != null)) | unique)
                })) as $grouped |
                
                ($grouped[] |
                    [
                        $repo,
                        $tag,
                        .date,
                        (.critical_ids | length),
                        (.critical_ids | join("; ")), 
                        (.high_ids | length),
                        (.high_ids | join("; ")),
                        (.medium_ids | length), 
                        (.medium_ids | join("; ")),
                        (.low_ids | length),
                        (.low_ids | join("; ")),
                        ((.critical_ids | length) + (.high_ids | length) + (.medium_ids | length) + (.low_ids | length))
                    ] | @csv
                )
            else
                empty
            end
            ' >> "$output_file" 2>/dev/null
            
            # Save summary data (just the unique CVEs for this repo)
            echo "$cve_data" | jq -r --arg repo "$repo" --arg tag "$tag" '
            if .items and (.items | length > 0) then
                ([.items[].critCveIds[]? // empty] | map(select(. != "" and . != null)) | unique | map("CRITICAL:" + .)[]),
                ([.items[].highCveIds[]? // empty] | map(select(. != "" and . != null)) | unique | map("HIGH:" + .)[]),
                ([.items[].medCveIds[]? // empty] | map(select(. != "" and . != null)) | unique | map("MEDIUM:" + .)[]),
                ([.items[].lowCveIds[]? // empty] | map(select(. != "" and . != null)) | unique | map("LOW:" + .)[])
            else
                empty
            end
            ' >> "$summary_file" 2>/dev/null
            
            processed_repos=$((processed_repos + 1))
        else
            echo "  Warning: No data returned for $repo:$tag" >&2
        fi
        
        # Small delay
        sleep 0.1
    else
        echo "  Warning: Invalid format '$line'" >&2
    fi
done < "$repo_file"

# Generate summary section
echo "" >> "$output_file"
echo "=== COMBINED SUMMARY ===" >> "$output_file"
echo "Metric,Value,Description" >> "$output_file"
echo "\"Date Range\",\"$from_date to $to_date\",\"Analysis period\"" >> "$output_file"
echo "\"Total Repositories\",$processed_repos,\"Successfully processed\"" >> "$output_file"

# Count unique CVEs by severity and collect the actual IDs
if [[ -f "$summary_file" ]]; then
    # Create temp files for each severity level
    temp_critical="$temp_dir/critical_cves.txt"
    temp_high="$temp_dir/high_cves.txt"
    temp_medium="$temp_dir/medium_cves.txt"
    temp_low="$temp_dir/low_cves.txt"
    
    # Extract and sort unique CVEs for each severity
    if [[ -s "$summary_file" ]]; then
        awk '/^CRITICAL:/ {print substr($0,10)}' "$summary_file" | sort | uniq > "$temp_critical"
        awk '/^HIGH:/ {print substr($0,6)}' "$summary_file" | sort | uniq > "$temp_high"
        awk '/^MEDIUM:/ {print substr($0,8)}' "$summary_file" | sort | uniq > "$temp_medium"
        awk '/^LOW:/ {print substr($0,5)}' "$summary_file" | sort | uniq > "$temp_low"
    else
        touch "$temp_critical" "$temp_high" "$temp_medium" "$temp_low"
    fi
    
    # Count CVEs
    critical_count=$(wc -l < "$temp_critical" | tr -d ' ')
    high_count=$(wc -l < "$temp_high" | tr -d ' ')
    medium_count=$(wc -l < "$temp_medium" | tr -d ' ')
    low_count=$(wc -l < "$temp_low" | tr -d ' ')
    
    # Get CVE lists (semicolon separated)
    critical_ids=$(tr '\n' '; ' < "$temp_critical" | sed 's/; $//')
    high_ids=$(tr '\n' '; ' < "$temp_high" | sed 's/; $//')
    medium_ids=$(tr '\n' '; ' < "$temp_medium" | sed 's/; $//')
    low_ids=$(tr '\n' '; ' < "$temp_low" | sed 's/; $//')
    
    total_unique=$((critical_count + high_count + medium_count + low_count))
    
    # Write summary with counts and IDs
    echo "\"Critical CVEs\",$critical_count,\"$critical_ids\"" >> "$output_file"
    echo "\"High CVEs\",$high_count,\"$high_ids\"" >> "$output_file"
    echo "\"Medium CVEs\",$medium_count,\"$medium_ids\"" >> "$output_file"
    echo "\"Low CVEs\",$low_count,\"$low_ids\"" >> "$output_file"
    echo "\"Total Unique CVEs\",$total_unique,\"All unique vulnerabilities across $processed_repos repositories\"" >> "$output_file"
else
    echo "\"Total Unique CVEs\",0,\"No vulnerability data found\"" >> "$output_file"
    critical_count=0
    high_count=0
    medium_count=0
    low_count=0
    total_unique=0
    critical_ids=""
    high_ids=""
    medium_ids=""
    low_ids=""
fi

# Cleanup
rm -rf "$temp_dir"

# Final status
echo "" >&2
echo "=== PROCESSING COMPLETE ===" >&2
echo "✓ Processed: $processed_repos/$total_repos repositories" >&2
echo "✓ Date range: $from_date to $to_date" >&2
echo "✓ Output: $output_file" >&2
echo "✓ Unique CVEs found:" >&2
echo "  - Critical: $critical_count" >&2
if [[ -n "$critical_ids" ]]; then
    echo "    IDs: $critical_ids" >&2
fi
echo "  - High: $high_count" >&2
if [[ -n "$high_ids" && ${#high_ids} -lt 200 ]]; then
    echo "    IDs: $high_ids" >&2
elif [[ -n "$high_ids" ]]; then
    echo "    IDs: $(echo "$high_ids" | cut -c1-150)... (truncated)" >&2
fi
echo "  - Medium: $medium_count" >&2
if [[ -n "$medium_ids" && ${#medium_ids} -lt 200 ]]; then
    echo "    IDs: $medium_ids" >&2
elif [[ -n "$medium_ids" ]]; then
    echo "    IDs: $(echo "$medium_ids" | cut -c1-150)... (truncated)" >&2
fi
echo "  - Low: $low_count" >&2
if [[ -n "$low_ids" && ${#low_ids} -lt 200 ]]; then
    echo "    IDs: $low_ids" >&2
elif [[ -n "$low_ids" ]]; then
    echo "    IDs: $(echo "$low_ids" | cut -c1-150)... (truncated)" >&2
fi
echo "  - Total: $total_unique" >&2

# Show file info
if [[ -f "$output_file" ]]; then
    rows=$(wc -l < "$output_file" | tr -d ' ')
    echo "✓ CSV file: $rows rows" >&2
fi