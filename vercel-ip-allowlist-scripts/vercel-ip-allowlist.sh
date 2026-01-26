#!/bin/bash
# =============================================================================
# Vercel IP Allowlist Script
# =============================================================================
#
# Creates a firewall rule that BLOCKS all traffic except from whitelisted IPs.
# This is different from bypass rules which only skip WAF checks.
#
# IMPORTANT:
# - Firewall is available on Pro and Enterprise plans
# - Changes affect traffic immediately
# - Firewall rules are PROJECT-SCOPED (not team/org-wide)
# - ALWAYS run with DRY_RUN=true first
#
# Usage:
#   ./vercel-ip-allowlist.sh apply vendor-ips.csv       # Create/update allowlist rule
#   ./vercel-ip-allowlist.sh show                       # Show current allowlist
#   ./vercel-ip-allowlist.sh disable                    # Disable the rule (don't delete)
#   ./vercel-ip-allowlist.sh remove                     # Remove the rule entirely
#   DRY_RUN=true ./vercel-ip-allowlist.sh apply vendor-ips.csv  # Preview
#
# Environment variables:
#   VERCEL_TOKEN (required): Vercel API token with read:project and write:project scopes
#   PROJECT_ID (required if not using --projects-file): Project ID or name
#   TEAM_ID (optional): Team ID if project belongs to a team
#   TEAM_SLUG (optional): Team slug (alternative to TEAM_ID)
#   DRY_RUN (optional): Set to "true" to preview without applying
#   HOSTNAME (optional): Hostname pattern for scoped rules (e.g., "api.crocs.com")
#   AUDIT_LOG (optional): Path to audit log file
#
# Security Notes:
#   - Never use curl -k or --insecure - all API calls must use verified TLS
#   - Store tokens in a secrets manager, not in env files committed to git
#   - Use minimal token scopes: read:project, write:project
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants & Configuration
# =============================================================================

readonly API_BASE="https://api.vercel.com"
readonly RATE_LIMIT_DELAY_MS=800
readonly RATE_LIMIT_BACKOFF_SEC=60
readonly MAX_RETRIES=3
readonly RULE_NAME="IP Allowlist - Auto-managed"
readonly RULE_DESCRIPTION="Block all traffic except whitelisted IPs. Managed by vercel-ip-allowlist.sh"
readonly MAX_IPS_PER_CONDITION=75  # Vercel limit per condition array

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

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

log_debug() {
  if [ "${DEBUG:-false}" = "true" ]; then
    echo -e "${BLUE}[DEBUG]${NC} $1"
  fi
}

# Safe string trimming
trim() {
  local var="$1"
  var="${var#"${var%%[![:space:]]*}"}"
  var="${var%"${var##*[![:space:]]}"}"
  echo "$var"
}

# Validate IPv4 address or CIDR
validate_ipv4() {
  local ip="$1"
  local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
  
  if [[ ! "$ip" =~ $ipv4_regex ]]; then
    return 1
  fi
  
  # Validate each octet is <= 255
  local ip_part="${ip%%/*}"
  IFS='.' read -ra octets <<< "$ip_part"
  for octet in "${octets[@]}"; do
    if [ "$octet" -gt 255 ]; then
      return 1
    fi
  done
  
  return 0
}

# Check for IPv6
is_ipv6() {
  local ip="$1"
  if [[ "$ip" =~ : ]]; then
    return 0
  fi
  return 1
}

# Write audit log entry
audit_log() {
  local action="$1"
  local details="$2"
  local log_file="${AUDIT_LOG:-}"
  
  if [ -n "$log_file" ]; then
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local user="${USER:-unknown}"
    echo "[${timestamp}] user=${user} project=${PROJECT_ID:-unknown} action=${action} ${details}" >> "$log_file"
  fi
}

# Rate limit sleep
rate_limit_sleep() {
  local ms="${1:-$RATE_LIMIT_DELAY_MS}"
  sleep "$(echo "scale=3; $ms / 1000" | bc)"
}

# =============================================================================
# API Functions
# =============================================================================

# Build team query parameter (supports both TEAM_ID and TEAM_SLUG)
get_team_param() {
  if [ -n "${TEAM_ID:-}" ]; then
    echo "teamId=${TEAM_ID}"
  elif [ -n "${TEAM_SLUG:-}" ]; then
    echo "slug=${TEAM_SLUG}"
  else
    echo ""
  fi
}

# Build query string with project and team
build_query_string() {
  local project_id="$1"
  local team_param
  team_param=$(get_team_param)
  
  if [ -n "$team_param" ]; then
    echo "?projectId=${project_id}&${team_param}"
  else
    echo "?projectId=${project_id}"
  fi
}

# Validate token and check API access
validate_token() {
  log_info "Validating API token..."
  
  local response
  response=$(api_request "GET" "/v2/user")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -ne 200 ]; then
    log_error "Token validation failed (HTTP $http_code)"
    log_error "Ensure your token has the required scopes: read:project, write:project"
    if [ -n "${TEAM_ID:-}${TEAM_SLUG:-}" ]; then
      log_error "For team projects, also ensure: read:team, write:team"
    fi
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
  
  local username
  username=$(echo "$body" | jq -r '.user.username // .username // "unknown"')
  log_info "Authenticated as: $username"
  return 0
}

# Make API request with retry logic
api_request() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"
  local attempt=1
  
  while [ $attempt -le $MAX_RETRIES ]; do
    local response
    local http_code
    
    log_debug "API request: $method $endpoint"
    
    if [ -n "$data" ]; then
      log_debug "Request body: $data"
      response=$(curl -s -w "\n%{http_code}" -X "$method" "${API_BASE}${endpoint}" \
        -H "Authorization: Bearer ${VERCEL_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$data")
    else
      response=$(curl -s -w "\n%{http_code}" -X "$method" "${API_BASE}${endpoint}" \
        -H "Authorization: Bearer ${VERCEL_TOKEN}" \
        -H "Content-Type: application/json")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')
    
    log_debug "Response code: $http_code"
    log_debug "Response body: $body"
    
    if [ "$http_code" -eq 429 ]; then
      log_warn "Rate limited (429). Backing off for ${RATE_LIMIT_BACKOFF_SEC}s... (attempt $attempt/$MAX_RETRIES)"
      audit_log "RATE_LIMITED" "attempt=$attempt backoff_sec=$RATE_LIMIT_BACKOFF_SEC"
      sleep "$RATE_LIMIT_BACKOFF_SEC"
      ((attempt++))
      continue
    fi
    
    echo "$body"
    echo "$http_code"
    return 0
  done
  
  echo "Max retries exceeded"
  echo "429"
  return 1
}

# Get current firewall configuration (active rules)
get_firewall_config() {
  local project_id="$1"
  local query_string
  query_string=$(build_query_string "$project_id")
  
  log_info "Fetching current firewall configuration..."
  
  local response
  response=$(api_request "GET" "/v1/security/firewall/config/active${query_string}")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -ne 200 ]; then
    log_error "Failed to get firewall config (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
  
  echo "$body"
}

# Find our managed allowlist rule in the config
find_allowlist_rule() {
  local config="$1"
  
  # Find rule by name
  local rule
  rule=$(echo "$config" | jq -c --arg name "$RULE_NAME" '.rules[] | select(.name == $name)' 2>/dev/null || echo "")
  
  if [ -n "$rule" ]; then
    echo "$rule"
    return 0
  fi
  
  return 1
}

# Create or update the allowlist rule
update_allowlist_rule() {
  local project_id="$1"
  local ips_json="$2"
  local action="$3"  # "insert" or "update"
  local existing_rule_id="${4:-}"
  local hostname="${HOSTNAME:-}"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  # Build conditions array
  local conditions
  if [ -n "$hostname" ]; then
    # Scoped to specific hostname
    conditions=$(jq -n \
      --arg hostname "$hostname" \
      --argjson ips "$ips_json" \
      '[
        {"type": "host", "op": "eq", "value": $hostname},
        {"type": "ip_address", "op": "ninc", "value": $ips}
      ]')
  else
    # Project-wide
    conditions=$(jq -n \
      --argjson ips "$ips_json" \
      '[{"type": "ip_address", "op": "ninc", "value": $ips}]')
  fi
  
  # Build the rule value
  local rule_value
  rule_value=$(jq -n \
    --arg name "$RULE_NAME" \
    --arg description "$RULE_DESCRIPTION" \
    --argjson conditions "$conditions" \
    '{
      name: $name,
      description: $description,
      active: true,
      conditionGroup: [{conditions: $conditions}],
      action: {
        mitigate: {
          action: "deny",
          rateLimit: null,
          redirect: null,
          actionDuration: null
        }
      }
    }')
  
  # Build the request body
  local request_body
  if [ "$action" = "update" ] && [ -n "$existing_rule_id" ]; then
    request_body=$(jq -n \
      --arg action "rules.update" \
      --arg id "$existing_rule_id" \
      --argjson value "$rule_value" \
      '{action: $action, id: $id, value: $value}')
  else
    request_body=$(jq -n \
      --arg action "rules.insert" \
      --argjson value "$rule_value" \
      '{action: $action, id: null, value: $value}')
  fi
  
  log_debug "Request body: $request_body"
  
  local response
  response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -eq 200 ]; then
    return 0
  else
    log_error "Failed to $action rule (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
}

# Disable the allowlist rule (set active=false)
disable_allowlist_rule() {
  local project_id="$1"
  local rule_id="$2"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    '{action: "rules.update", id: $id, value: {active: false}}')
  
  local response
  response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -eq 200 ]; then
    return 0
  else
    log_error "Failed to disable rule (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
}

# Remove the allowlist rule
remove_allowlist_rule() {
  local project_id="$1"
  local rule_id="$2"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    '{action: "rules.remove", id: $id}')
  
  local response
  response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -eq 200 ]; then
    return 0
  else
    log_error "Failed to remove rule (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  fi
}

# =============================================================================
# CSV Parsing
# =============================================================================

# Parse a single CSV line respecting quoted fields
# Handles: commas inside quotes, escaped quotes (""), single quotes (no escaping needed)
# Sets global array: CSV_FIELDS
parse_csv_line() {
  local line="$1"
  CSV_FIELDS=()
  local field=""
  local in_quotes=false
  local i=0
  local len=${#line}
  
  while [ $i -lt $len ]; do
    local char="${line:$i:1}"
    local next_char="${line:$((i+1)):1}"
    
    if [ "$in_quotes" = true ]; then
      if [ "$char" = '"' ]; then
        if [ "$next_char" = '"' ]; then
          # Escaped quote ("") - add single quote and skip next
          field+="$char"
          ((i++))
        else
          # End of quoted field
          in_quotes=false
        fi
      else
        field+="$char"
      fi
    else
      if [ "$char" = '"' ]; then
        # Start of quoted field
        in_quotes=true
      elif [ "$char" = ',' ]; then
        # Field separator - save current field and start new one
        CSV_FIELDS+=("$field")
        field=""
      else
        field+="$char"
      fi
    fi
    ((i++))
  done
  
  # Add the last field
  CSV_FIELDS+=("$field")
}

parse_csv() {
  local csv_file="$1"
  local ips_array="[]"
  local line_num=0
  local valid_count=0
  local error_count=0
  
  log_info "Parsing CSV file: $csv_file"
  
  while IFS= read -r line || [ -n "$line" ]; do
    ((line_num++))
    
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
    # Parse CSV line respecting quotes
    parse_csv_line "$line"
    
    # Extract fields
    local ip="${CSV_FIELDS[0]:-}"
    local vendor_name="${CSV_FIELDS[1]:-}"
    local notes="${CSV_FIELDS[2]:-}"
    
    # Trim whitespace
    ip=$(trim "$ip")
    vendor_name=$(trim "$vendor_name")
    notes=$(trim "$notes")
    
    # Skip header row
    if [ "$ip" = "ip" ]; then
      continue
    fi
    
    # Skip if no IP
    if [ -z "$ip" ]; then
      continue
    fi
    
    # Check for IPv6
    if is_ipv6 "$ip"; then
      log_error "Line $line_num: IPv6 not supported - $ip"
      ((error_count++))
      continue
    fi
    
    # Validate IPv4
    if ! validate_ipv4 "$ip"; then
      log_error "Line $line_num: Invalid IP format - $ip"
      ((error_count++))
      continue
    fi
    
    # Add to IPs array
    ips_array=$(echo "$ips_array" | jq --arg ip "$ip" '. + [$ip]')
    ((valid_count++))
    
    log_debug "Line $line_num: $ip ($vendor_name)"
    
  done < "$csv_file"
  
  log_info "Parsed $valid_count valid IPs ($error_count errors)"
  
  if [ "$error_count" -gt 0 ]; then
    log_warn "Some IPs had validation errors. Review the errors above."
  fi
  
  echo "$ips_array"
}

# =============================================================================
# Commands
# =============================================================================

cmd_apply() {
  local csv_file="$1"
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  if [ ! -f "$csv_file" ]; then
    log_error "CSV file not found: $csv_file"
    exit 1
  fi
  
  # Parse CSV
  local ips_json
  ips_json=$(parse_csv "$csv_file")
  
  local ip_count
  ip_count=$(echo "$ips_json" | jq 'length')
  
  if [ "$ip_count" -eq 0 ]; then
    log_error "No valid IPs found in CSV"
    exit 1
  fi
  
  # Check for IP limit
  if [ "$ip_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
    log_warn "IP count ($ip_count) exceeds recommended limit ($MAX_IPS_PER_CONDITION per condition)"
    log_warn "Vercel may have limits on IPs per condition. Consider splitting into multiple rules."
  fi
  
  echo ""
  log_info "IPs to allowlist: $ip_count"
  log_info "Hostname scope: ${HOSTNAME:-project-wide}"
  echo ""
  
  # Preview
  log_info "Preview (first 10 IPs):"
  echo "$ips_json" | jq '.[0:10]'
  echo ""
  
  # Dry run check
  if [ "${DRY_RUN:-false}" = "true" ]; then
    echo "=============================================="
    echo "  DRY RUN - No changes made"
    echo "=============================================="
    echo ""
    echo "Would create/update allowlist rule with $ip_count IPs."
    echo "All traffic from IPs NOT in this list will be BLOCKED."
    echo ""
    echo "To apply changes, run without DRY_RUN=true"
    exit 0
  fi
  
  # Get current config
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  # Check for existing rule
  local existing_rule
  existing_rule=$(find_allowlist_rule "$config" || echo "")
  
  local action="insert"
  local existing_rule_id=""
  
  if [ -n "$existing_rule" ]; then
    existing_rule_id=$(echo "$existing_rule" | jq -r '.id')
    local existing_ip_count
    existing_ip_count=$(echo "$existing_rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value | length' 2>/dev/null || echo "0")
    
    log_info "Found existing allowlist rule (ID: $existing_rule_id)"
    log_info "Current IP count: $existing_ip_count"
    action="update"
  fi
  
  # Confirm
  echo ""
  echo "=============================================="
  echo "  WARNING"
  echo "=============================================="
  echo ""
  if [ "$action" = "update" ]; then
    echo "This will UPDATE the existing allowlist rule."
  else
    echo "This will CREATE a new allowlist rule."
  fi
  echo ""
  echo "EFFECT: All traffic from IPs NOT in this list will be BLOCKED."
  echo ""
  echo "IPs to allowlist: $ip_count"
  echo ""
  read -p "Are you sure you want to proceed? Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo ""
    echo "Aborted. No changes were made."
    exit 1
  fi
  
  # Apply the rule
  log_info "Applying allowlist rule..."
  
  if update_allowlist_rule "$project_id" "$ips_json" "$action" "$existing_rule_id"; then
    echo ""
    echo "=============================================="
    echo "  SUCCESS"
    echo "=============================================="
    echo ""
    log_info "Allowlist rule ${action}ed successfully!"
    log_info "Whitelisted IPs: $ip_count"
    log_info "All other traffic will be BLOCKED."
    audit_log "ALLOWLIST_${action^^}" "ip_count=$ip_count"
  else
    log_error "Failed to $action allowlist rule"
    audit_log "ALLOWLIST_${action^^}_FAILED" "ip_count=$ip_count"
    exit 1
  fi
}

cmd_show() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching allowlist rule for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  echo ""
  echo "=============================================="
  echo "  IP Allowlist for $project_id"
  echo "=============================================="
  echo ""
  
  if [ -z "$rule" ]; then
    echo "No allowlist rule configured."
    echo ""
    echo "Use './vercel-ip-allowlist.sh apply vendor-ips.csv' to create one."
  else
    local rule_id
    rule_id=$(echo "$rule" | jq -r '.id')
    local active
    active=$(echo "$rule" | jq -r '.active')
    local ips
    ips=$(echo "$rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value')
    local ip_count
    ip_count=$(echo "$ips" | jq 'length')
    local hostname
    hostname=$(echo "$rule" | jq -r '.conditionGroup[0].conditions[] | select(.type == "host") | .value // empty')
    
    echo "Rule ID:     $rule_id"
    echo "Status:      $([ "$active" = "true" ] && echo "ACTIVE" || echo "DISABLED")"
    echo "IP Count:    $ip_count"
    echo "Scope:       ${hostname:-project-wide}"
    echo ""
    echo "Whitelisted IPs:"
    echo "$ips" | jq -r '.[]' | while read -r ip; do
      echo "  - $ip"
    done
  fi
  echo ""
}

cmd_disable() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching allowlist rule for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  if [ -z "$rule" ]; then
    log_error "No allowlist rule found"
    exit 1
  fi
  
  local rule_id
  rule_id=$(echo "$rule" | jq -r '.id')
  local active
  active=$(echo "$rule" | jq -r '.active')
  
  if [ "$active" = "false" ]; then
    log_info "Rule is already disabled"
    exit 0
  fi
  
  echo ""
  log_warn "This will DISABLE the allowlist rule."
  log_warn "All traffic will be allowed until the rule is re-enabled."
  echo ""
  read -p "Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 1
  fi
  
  if disable_allowlist_rule "$project_id" "$rule_id"; then
    log_info "Allowlist rule disabled successfully"
    audit_log "ALLOWLIST_DISABLED" "rule_id=$rule_id"
  else
    log_error "Failed to disable rule"
    exit 1
  fi
}

cmd_remove() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  
  log_info "Fetching allowlist rule for project $project_id..."
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local rule
  rule=$(find_allowlist_rule "$config" || echo "")
  
  if [ -z "$rule" ]; then
    log_error "No allowlist rule found"
    exit 1
  fi
  
  local rule_id
  rule_id=$(echo "$rule" | jq -r '.id')
  
  echo ""
  log_warn "This will PERMANENTLY DELETE the allowlist rule."
  log_warn "All traffic will be allowed after deletion."
  echo ""
  read -p "Type 'DELETE' to confirm: " CONFIRM
  if [ "$CONFIRM" != "DELETE" ]; then
    echo "Aborted."
    exit 1
  fi
  
  if remove_allowlist_rule "$project_id" "$rule_id"; then
    log_info "Allowlist rule removed successfully"
    audit_log "ALLOWLIST_REMOVED" "rule_id=$rule_id"
  else
    log_error "Failed to remove rule"
    exit 1
  fi
}

cmd_backup() {
  local project_id="${PROJECT_ID:?PROJECT_ID is required}"
  local backup_dir="${BACKUP_DIR:-./backups}"
  
  log_info "Creating backup of firewall configuration..."
  
  # Create backup directory
  mkdir -p "$backup_dir"
  chmod 700 "$backup_dir"
  
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  local timestamp
  timestamp=$(date +"%Y%m%d-%H%M%S")
  local backup_file="${backup_dir}/backup-${project_id}-${timestamp}.json"
  
  # Build backup structure
  jq -n \
    --arg project_id "$project_id" \
    --arg team_id "${TEAM_ID:-}" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg user "${USER:-unknown}" \
    --argjson config "$config" \
    '{
      metadata: {
        project_id: $project_id,
        team_id: $team_id,
        backup_timestamp: $timestamp,
        backup_user: $user,
        type: "firewall_config"
      },
      config: $config
    }' > "$backup_file"
  
  chmod 600 "$backup_file"
  
  log_info "Backup created: $backup_file"
  audit_log "BACKUP_CREATED" "file=$backup_file"
}

show_usage() {
  cat << EOF
Vercel IP Allowlist Script

DESCRIPTION:
  Creates a firewall rule that BLOCKS all traffic except from whitelisted IPs.
  This is different from bypass rules which only skip WAF checks.

USAGE:
  $0 apply <csv_file>     Create/update allowlist rule with IPs from CSV
  $0 show                 Show current allowlist configuration
  $0 disable              Disable the allowlist rule (keeps config)
  $0 remove               Remove the allowlist rule entirely
  $0 backup               Export current firewall configuration
  $0 --help               Show this help message

OPTIONS:
  --projects-file <file>  File containing list of project IDs (one per line)
  --help                  Show this help message

ENVIRONMENT VARIABLES:
  VERCEL_TOKEN   (required) Vercel API token with read:project, write:project scopes
  PROJECT_ID     (required) Project ID
  TEAM_ID        (optional) Team ID if project belongs to a team
  TEAM_SLUG      (optional) Team slug (alternative to TEAM_ID)
  HOSTNAME       (optional) Hostname pattern for scoped rules (e.g., "api.crocs.com")
  DRY_RUN        (optional) Set to "true" for preview mode
  AUDIT_LOG      (optional) Path to audit log file
  DEBUG          (optional) Set to "true" for verbose output
  BACKUP_DIR     (optional) Directory for backups (default: ./backups)

CSV FORMAT:
  ip,vendor_name,notes
  1.2.3.4,Acme Corp,Payment gateway
  5.6.7.0/24,Partner Inc,API integration

EXAMPLES:
  # Preview changes (dry run)
  DRY_RUN=true PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh apply vendor-ips.csv

  # Apply allowlist rule
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh apply vendor-ips.csv

  # Show current configuration
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh show

  # Disable rule temporarily
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh disable

  # Remove rule completely
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh remove

  # Scope to specific hostname
  HOSTNAME="api.crocs.com" PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh apply vendor-ips.csv

BEHAVIOR COMPARISON:
  Bypass Rules:        Whitelisted IPs skip WAF, ALL traffic reaches app
  Allowlist (this):    ONLY whitelisted IPs reach app, all others BLOCKED

EOF
}

# =============================================================================
# Main
# =============================================================================

main() {
  # Check dependencies
  if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null; then
    log_error "Required dependencies: curl, jq"
    exit 1
  fi
  
  if ! command -v bc &> /dev/null; then
    log_error "Required dependency: bc"
    exit 1
  fi
  
  # Check token
  if [ -z "${VERCEL_TOKEN:-}" ]; then
    log_error "VERCEL_TOKEN environment variable is not set"
    exit 1
  fi
  
  if [ $# -eq 0 ]; then
    show_usage
    exit 1
  fi
  
  local command="$1"
  shift
  
  case "$command" in
    apply)
      if [ -z "${1:-}" ]; then
        log_error "CSV file required"
        echo "Usage: $0 apply <csv_file>"
        exit 1
      fi
      
      # Validate token before proceeding
      if ! validate_token; then
        exit 1
      fi
      echo ""
      
      cmd_apply "$1"
      ;;
    show)
      if ! validate_token; then
        exit 1
      fi
      cmd_show
      ;;
    disable)
      if ! validate_token; then
        exit 1
      fi
      cmd_disable
      ;;
    remove)
      if ! validate_token; then
        exit 1
      fi
      cmd_remove
      ;;
    backup)
      if ! validate_token; then
        exit 1
      fi
      cmd_backup
      ;;
    --help|-h)
      show_usage
      exit 0
      ;;
    *)
      log_error "Unknown command: $command"
      show_usage
      exit 1
      ;;
  esac
}

main "$@"
