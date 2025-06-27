# Historical CVE Analysis Scripts

Generate historical CVE reports for customer's entitled images using the Chainguard Enforce API.

## Prerequisites

- **bash** (3.0+)
- **curl** and **jq**
- **chainctl** (authenticated with `chainctl auth login`)

Install dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install curl jq

# macOS
brew install jq
```

## Quick Start

1. **Create repository list** (`repos.txt`):
```
cgr.dev/chainguard-private/airflow:latest
cgr.dev/chainguard-private/nginx:stable
cgr.dev/chainguard-private/postgres:15
```

2. **Run the script**:
```bash
chmod +x script.sh
./script.sh repos.txt cve_report.csv
```

## Output Format

The CSV report contains:

**Main Data:**
```csv
Repository,Tag,Date,Critical_Count,Critical_IDs,High_Count,High_IDs,Medium_Count,Medium_IDs,Low_Count,Low_IDs,Total_Count
cgr.dev/chainguard-private/app,latest,2025-06-11T00:00:00Z,1,"GHSA-xxxx",2,"GHSA-yyyy; GHSA-zzzz",0,"",1,"CVE-2025-001",4
```

**Summary Section:**
```csv
=== COMBINED SUMMARY ===
Metric,Value,Description
"Critical CVEs",1,"GHSA-xxxx-xxxx-xxxx"
"High CVEs",3,"GHSA-yyyy-yyyy-yyyy; GHSA-zzzz-zzzz-zzzz; GHSA-aaaa-aaaa-aaaa"
"Total Unique CVEs",12,"All unique vulnerabilities across all repositories"
```

## Examples

**Basic usage:**
```bash
./script.sh <repo_list_file> <output_file> [from_date] [to_date]
```

**Interactive Mode (Recommended):**
```bash
/script.sh repos.txt vulnerability_report.csv
```
When run without date parameters, the script will prompt you to choose:

Number of days back (e.g., 7, 30, 90 days)
Custom date range with specific start/end dates


**Command Line Mode:**
```bash
./script.sh repos.txt report.csv 2025-05-01T00:00:00Z 2025-06-11T00:00:00Z
```

## Troubleshooting

**Authentication error:**
```bash
chainctl auth login
```

**No data returned:**
- Verify repository names and tags
- Check date range (scripts default to last 30 days)
- Ensure repository access permissions

**Permission denied:**
```bash
chmod +x script.sh
```
