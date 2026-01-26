#!/bin/bash
# =============================================================================
# Cloudflare IP Allowlist Export Script
# =============================================================================
#
# Exports IP addresses from Cloudflare IP Access Rules or IP Lists to CSV
# format compatible with Vercel Firewall bypass import.
#
# IMPORTANT:
# - Requires Cloudflare API Token with "Account Firewall Access Rules Read" 
#   or "Zone Firewall Access Rules Read" permissions
# - No UI export is available in Cloudflare - API is the only option
# - Handles pagination for large lists (600+ IPs)
#
# Usage:
#   # Export account-level IP Access Rules
#   ./cloudflare-export.sh --account <account_id>
#
#   # Export zone-level IP Access Rules  
#   ./cloudflare-export.sh --zone <zone_id>
#
#   # Export from IP List
#   ./cloudflare-export.sh --list <account_id> <list_id>
#
#   # Export all lists from an account
#   ./cloudflare-export.sh --all-lists <account_id>
#
# Environment variables:
#   CF_API_TOKEN (required): Cloudflare API token
#   OUTPUT_FILE (optional): Output CSV file path (default: cloudflare_ips.csv)
#   MODE_FILTER (optional): Filter by mode - whitelist, block, challenge (default: whitelist)
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly CF_API_BASE="https://api.cloudflare.com/client/v4"
readonly DEFAULT_PER_PAGE=100
readonly MAX_PER_PAGE=1000

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# =============================================================================
# Utility Functions
# =============================================================================

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

check_dependencies() {
  local missing=()
  
  if ! command -v curl &> /dev/null; then
    missing+=("curl")
  fi
  
  if ! command -v jq &> /dev/null; then
    missing+=("jq")
  fi
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required dependencies: ${missing[*]}"
    log_error "Please install them and try again."
    exit 1
  fi
}

validate_token() {
  if [ -z "${CF_API_TOKEN:-}" ]; then
    log_error "CF_API_TOKEN environment variable is not set"
    echo ""
    echo "Set your Cloudflare API token:"
    echo "  export CF_API_TOKEN='your-cloudflare-api-token'"
    echo ""
    echo "Create a token at: https://dash.cloudflare.com/profile/api-tokens"
    echo "Required permissions: Account Firewall Access Rules Read"
    exit 1
  fi
}

show_usage() {
  cat << EOF
Cloudflare IP Allowlist Export Script

USAGE:
  $0 --account <account_id>              Export account-level IP Access Rules
  $0 --zone <zone_id>                    Export zone-level IP Access Rules
  $0 --list <account_id> <list_id>       Export items from a specific IP List
  $0 --all-lists <account_id>            List all IP Lists in an account
  $0 --help                              Show this help message

ENVIRONMENT VARIABLES:
  CF_API_TOKEN    (required) Cloudflare API token
  OUTPUT_FILE     (optional) Output CSV file path (default: cloudflare_ips.csv)
  MODE_FILTER     (optional) Filter by mode: whitelist, block, challenge (default: whitelist)

EXAMPLES:
  # Export all whitelisted IPs from account
  CF_API_TOKEN="token" ./cloudflare-export.sh --account abc123def456

  # Export to specific file
  OUTPUT_FILE="vendor_ips.csv" ./cloudflare-export.sh --account abc123def456

  # Export all modes (not just whitelist)
  MODE_FILTER="" ./cloudflare-export.sh --zone xyz789

OUTPUT FORMAT:
  CSV with columns: ip,notes,mode,created_on
  Compatible with Vercel Firewall bypass import scripts

EOF
}

# =============================================================================
# API Functions
# =============================================================================

# Make authenticated API request
cf_api_request() {
  local endpoint="$1"
  local response
  
  response=$(curl -s -w "\n%{http_code}" \
    "${CF_API_BASE}${endpoint}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -ne 200 ]; then
    log_error "API request failed (HTTP $http_code)"
    log_error "Endpoint: $endpoint"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
  
  # Check Cloudflare success field
  local success
  success=$(echo "$body" | jq -r '.success')
  if [ "$success" != "true" ]; then
    log_error "Cloudflare API returned success=false"
    echo "$body" | jq '.errors' 2>/dev/null
    return 1
  fi
  
  echo "$body"
}

# Export IP Access Rules (account or zone level)
export_ip_access_rules() {
  local scope="$1"  # "accounts" or "zones"
  local id="$2"     # account_id or zone_id
  local output_file="${OUTPUT_FILE:-cloudflare_ips.csv}"
  local mode_filter="${MODE_FILTER:-whitelist}"
  
  log_info "Exporting IP Access Rules from $scope/$id"
  log_info "Mode filter: ${mode_filter:-all}"
  log_info "Output file: $output_file"
  echo ""
  
  # Build query params
  local query_params="per_page=${DEFAULT_PER_PAGE}"
  if [ -n "$mode_filter" ]; then
    query_params="${query_params}&mode=${mode_filter}"
  fi
  
  # Write CSV header
  echo "ip,notes,mode,created_on" > "$output_file"
  
  local page=1
  local total_count=0
  local total_pages=1
  
  while [ "$page" -le "$total_pages" ]; do
    log_info "Fetching page $page..."
    
    local response
    response=$(cf_api_request "/${scope}/${id}/firewall/access_rules/rules?${query_params}&page=${page}")
    
    if [ $? -ne 0 ]; then
      log_error "Failed to fetch page $page"
      return 1
    fi
    
    # Extract pagination info
    total_pages=$(echo "$response" | jq -r '.result_info.total_pages // 1')
    local page_count
    page_count=$(echo "$response" | jq -r '.result_info.count // 0')
    
    if [ "$page" -eq 1 ]; then
      total_count=$(echo "$response" | jq -r '.result_info.total_count // 0')
      log_info "Total rules to export: $total_count (across $total_pages pages)"
    fi
    
    # Extract and format results
    echo "$response" | jq -r '.result[] | [
      .configuration.value,
      (.notes // "" | gsub(","; ";") | gsub("\n"; " ")),
      .mode,
      .created_on
    ] | @csv' >> "$output_file"
    
    log_info "  Page $page: $page_count rules exported"
    
    ((page++))
  done
  
  echo ""
  log_info "Export complete!"
  log_info "Total rules exported: $total_count"
  log_info "Output file: $output_file"
  
  # Show sample
  echo ""
  log_info "First 5 entries:"
  head -6 "$output_file" | tail -5
}

# List all IP Lists in an account
list_ip_lists() {
  local account_id="$1"
  
  log_info "Fetching IP Lists from account $account_id"
  echo ""
  
  local response
  response=$(cf_api_request "/accounts/${account_id}/rules/lists")
  
  if [ $? -ne 0 ]; then
    return 1
  fi
  
  echo "$response" | jq -r '.result[] | select(.kind == "ip") | "ID: \(.id)\n  Name: \(.name)\n  Description: \(.description // "N/A")\n  Item Count: \(.num_items)\n  Created: \(.created_on)\n"'
  
  local list_count
  list_count=$(echo "$response" | jq '[.result[] | select(.kind == "ip")] | length')
  
  echo ""
  log_info "Found $list_count IP lists"
  echo ""
  echo "To export a specific list, run:"
  echo "  $0 --list $account_id <list_id>"
}

# Export items from a specific IP List
export_ip_list() {
  local account_id="$1"
  local list_id="$2"
  local output_file="${OUTPUT_FILE:-cloudflare_ips.csv}"
  
  log_info "Exporting IP List $list_id from account $account_id"
  log_info "Output file: $output_file"
  echo ""
  
  # Get list metadata first
  local list_info
  list_info=$(cf_api_request "/accounts/${account_id}/rules/lists/${list_id}")
  
  if [ $? -ne 0 ]; then
    return 1
  fi
  
  local list_name
  list_name=$(echo "$list_info" | jq -r '.result.name')
  local item_count
  item_count=$(echo "$list_info" | jq -r '.result.num_items')
  
  log_info "List name: $list_name"
  log_info "Expected items: $item_count"
  echo ""
  
  # Write CSV header
  echo "ip,notes,mode,created_on" > "$output_file"
  
  # Fetch all items (uses cursor-based pagination)
  local cursor=""
  local total_exported=0
  local page=1
  
  while true; do
    log_info "Fetching page $page..."
    
    local endpoint="/accounts/${account_id}/rules/lists/${list_id}/items"
    if [ -n "$cursor" ]; then
      endpoint="${endpoint}?cursor=${cursor}"
    fi
    
    local response
    response=$(cf_api_request "$endpoint")
    
    if [ $? -ne 0 ]; then
      return 1
    fi
    
    # Extract items
    local page_count
    page_count=$(echo "$response" | jq '.result | length')
    
    echo "$response" | jq -r '.result[] | [
      .ip,
      (.comment // "" | gsub(","; ";") | gsub("\n"; " ")),
      "whitelist",
      .created_on
    ] | @csv' >> "$output_file"
    
    total_exported=$((total_exported + page_count))
    log_info "  Page $page: $page_count items exported (total: $total_exported)"
    
    # Check for more pages
    cursor=$(echo "$response" | jq -r '.result_info.cursors.after // empty')
    if [ -z "$cursor" ]; then
      break
    fi
    
    ((page++))
  done
  
  echo ""
  log_info "Export complete!"
  log_info "Total items exported: $total_exported"
  log_info "Output file: $output_file"
  
  # Show sample
  echo ""
  log_info "First 5 entries:"
  head -6 "$output_file" | tail -5
}

# =============================================================================
# Conversion to Vercel Format
# =============================================================================

convert_to_vercel_format() {
  local input_file="$1"
  local output_file="${2:-vercel_ips.csv}"
  
  log_info "Converting $input_file to Vercel format..."
  
  # Vercel format: ip,note (note is optional, max 500 chars for bypass API)
  # Truncate notes to 500 chars and combine with mode info
  
  echo "ip,note" > "$output_file"
  
  tail -n +2 "$input_file" | while IFS=, read -r ip notes mode created_on; do
    # Remove quotes if present
    ip=$(echo "$ip" | tr -d '"')
    notes=$(echo "$notes" | tr -d '"')
    mode=$(echo "$mode" | tr -d '"')
    
    # Combine notes with mode info, truncate to 500 chars
    local combined_note="${notes}"
    if [ -n "$combined_note" ]; then
      combined_note="${combined_note:0:500}"
    fi
    
    echo "\"$ip\",\"$combined_note\""
  done >> "$output_file"
  
  log_info "Converted to: $output_file"
}

# =============================================================================
# Main
# =============================================================================

main() {
  check_dependencies
  validate_token
  
  if [ $# -eq 0 ]; then
    show_usage
    exit 1
  fi
  
  case "$1" in
    --account)
      if [ -z "${2:-}" ]; then
        log_error "Account ID required"
        echo "Usage: $0 --account <account_id>"
        exit 1
      fi
      export_ip_access_rules "accounts" "$2"
      ;;
    
    --zone)
      if [ -z "${2:-}" ]; then
        log_error "Zone ID required"
        echo "Usage: $0 --zone <zone_id>"
        exit 1
      fi
      export_ip_access_rules "zones" "$2"
      ;;
    
    --list)
      if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
        log_error "Account ID and List ID required"
        echo "Usage: $0 --list <account_id> <list_id>"
        exit 1
      fi
      export_ip_list "$2" "$3"
      ;;
    
    --all-lists)
      if [ -z "${2:-}" ]; then
        log_error "Account ID required"
        echo "Usage: $0 --all-lists <account_id>"
        exit 1
      fi
      list_ip_lists "$2"
      ;;
    
    --convert)
      if [ -z "${2:-}" ]; then
        log_error "Input file required"
        echo "Usage: $0 --convert <input_csv> [output_csv]"
        exit 1
      fi
      convert_to_vercel_format "$2" "${3:-vercel_ips.csv}"
      ;;
    
    --help|-h)
      show_usage
      exit 0
      ;;
    
    *)
      log_error "Unknown option: $1"
      show_usage
      exit 1
      ;;
  esac
}

main "$@"
