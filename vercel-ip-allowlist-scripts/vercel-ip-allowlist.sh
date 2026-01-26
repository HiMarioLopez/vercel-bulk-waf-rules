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
#   RULE_HOSTNAME (optional): Hostname pattern for scoped rules (e.g., "api.crocs.com")
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
  echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
  if [ "${DEBUG:-false}" = "true" ]; then
    echo -e "${BLUE}[DEBUG]${NC} $1" >&2
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

# =============================================================================
# CIDR Aggregation Functions
# =============================================================================

# Convert IP to 32-bit integer
ip_to_int() {
  local ip="$1"
  local ip_part="${ip%%/*}"
  IFS='.' read -ra octets <<< "$ip_part"
  echo $(( (${octets[0]} << 24) + (${octets[1]} << 16) + (${octets[2]} << 8) + ${octets[3]} ))
}

# Convert 32-bit integer to IP
int_to_ip() {
  local int="$1"
  echo "$(( (int >> 24) & 255 )).$(( (int >> 16) & 255 )).$(( (int >> 8) & 255 )).$(( int & 255 ))"
}

# Get CIDR prefix for a block size (block size must be power of 2)
block_size_to_prefix() {
  local size="$1"
  local prefix=32
  local s=1
  while [ "$s" -lt "$size" ]; do
    s=$((s * 2))
    prefix=$((prefix - 1))
  done
  echo "$prefix"
}

# Check if IP is aligned to a given block size
is_aligned() {
  local ip_int="$1"
  local block_size="$2"
  [ $((ip_int % block_size)) -eq 0 ]
}

# Find the largest CIDR block that fits starting at ip_int and covering up to max_count IPs
# Returns: "prefix count" where prefix is the CIDR prefix and count is how many IPs it covers
find_largest_cidr() {
  local ip_int="$1"
  local max_count="$2"
  
  local best_prefix=32
  local best_count=1
  
  # Try progressively larger block sizes (must be power of 2 and aligned)
  local block_size=1
  while [ "$block_size" -le "$max_count" ]; do
    # Check alignment
    if is_aligned "$ip_int" "$block_size"; then
      best_prefix=$(block_size_to_prefix "$block_size")
      best_count="$block_size"
    else
      # Not aligned for this size, stop
      break
    fi
    block_size=$((block_size * 2))
  done
  
  echo "$best_prefix $best_count"
}

# Aggregate a sorted list of IP integers into CIDR blocks
# Input: newline-separated list of IP integers (sorted)
# Output: newline-separated list of CIDR notations
aggregate_ips_to_cidrs() {
  local ip_ints="$1"
  local result=""
  
  # Convert to array (compatible with bash 3.x on macOS)
  local -a ips=()
  while IFS= read -r line; do
    [ -n "$line" ] && ips+=("$line")
  done <<< "$ip_ints"
  
  local count=${#ips[@]}
  if [ "$count" -eq 0 ]; then
    return
  fi
  
  local i=0
  while [ "$i" -lt "$count" ]; do
    local start_ip="${ips[$i]}"
    
    # Find contiguous range starting at this IP
    local range_end="$i"
    while [ "$((range_end + 1))" -lt "$count" ]; do
      local next_ip="${ips[$((range_end + 1))]}"
      if [ "$next_ip" -eq "$((ips[range_end] + 1))" ]; then
        range_end=$((range_end + 1))
      else
        break
      fi
    done
    
    local range_count=$((range_end - i + 1))
    
    # Greedily assign CIDR blocks to cover this contiguous range
    local pos="$i"
    while [ "$pos" -le "$range_end" ]; do
      local remaining=$((range_end - pos + 1))
      local current_ip="${ips[$pos]}"
      
      # Find largest valid CIDR starting at current_ip covering up to remaining IPs
      local cidr_info
      cidr_info=$(find_largest_cidr "$current_ip" "$remaining")
      local prefix
      prefix=$(echo "$cidr_info" | cut -d' ' -f1)
      local covered
      covered=$(echo "$cidr_info" | cut -d' ' -f2)
      
      # Output CIDR
      local ip_str
      ip_str=$(int_to_ip "$current_ip")
      if [ "$prefix" -eq 32 ]; then
        result="${result}${ip_str}"$'\n'
      else
        result="${result}${ip_str}/${prefix}"$'\n'
      fi
      
      pos=$((pos + covered))
    done
    
    i=$((range_end + 1))
  done
  
  echo -n "$result"
}

# Main CIDR optimization function
# Input: JSON array of IPs (may include existing CIDRs)
# Output: JSON array of optimized IPs/CIDRs
optimize_ip_list() {
  local ips_json="$1"
  
  # Separate individual IPs from existing CIDRs
  local individual_ips
  individual_ips=$(echo "$ips_json" | jq -r '.[] | select(contains("/") | not)')
  
  local existing_cidrs
  existing_cidrs=$(echo "$ips_json" | jq -r '.[] | select(contains("/"))')
  
  # Convert individual IPs to integers and sort
  local ip_ints=""
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    local ip_int
    ip_int=$(ip_to_int "$ip")
    ip_ints="${ip_ints}${ip_int}"$'\n'
  done <<< "$individual_ips"
  
  # Sort integers
  local sorted_ints
  sorted_ints=$(echo -n "$ip_ints" | sort -n | uniq)
  
  # Aggregate to CIDRs
  local aggregated
  aggregated=$(aggregate_ips_to_cidrs "$sorted_ints")
  
  # Combine with existing CIDRs and output as JSON
  local all_entries=""
  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    all_entries="${all_entries}${entry}"$'\n'
  done <<< "$aggregated"
  
  while IFS= read -r cidr; do
    [ -z "$cidr" ] && continue
    all_entries="${all_entries}${cidr}"$'\n'
  done <<< "$existing_cidrs"
  
  # Convert to JSON array (deduplicated)
  echo -n "$all_entries" | sort -u | jq -R -s 'split("\n") | map(select(length > 0))'
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
# Auto-detect from Vercel CLI
# =============================================================================

# Fetch team slug from Vercel API using team ID
# Some Vercel API endpoints prefer slug over teamId
fetch_team_slug() {
  local team_id="$1"
  
  if [ -z "$team_id" ] || [ -z "${VERCEL_TOKEN:-}" ]; then
    return 1
  fi
  
  log_debug "Fetching team slug for: $team_id"
  
  local response
  response=$(curl -s -w "\n%{http_code}" -X GET "${API_BASE}/v2/teams/${team_id}" \
    -H "Authorization: Bearer ${VERCEL_TOKEN}" \
    -H "Content-Type: application/json" 2>/dev/null)
  
  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -eq 200 ]; then
    local slug
    slug=$(echo "$body" | jq -r '.slug // empty' 2>/dev/null)
    if [ -n "$slug" ]; then
      echo "$slug"
      return 0
    fi
  fi
  
  return 1
}

# Try to load PROJECT_ID and TEAM_ID from .vercel/project.json
# This file is created by `vercel link`
auto_detect_vercel_config() {
  local search_dir="${1:-.}"
  local vercel_config=""
  
  # Search for .vercel/project.json in current dir and parent dirs
  local dir="$search_dir"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/.vercel/project.json" ]; then
      vercel_config="$dir/.vercel/project.json"
      break
    fi
    dir=$(dirname "$dir")
  done
  
  if [ -z "$vercel_config" ]; then
    return 1
  fi
  
  log_debug "Found Vercel config: $vercel_config"
  
  # Extract projectId and orgId (team ID)
  local project_id
  local org_id
  project_id=$(jq -r '.projectId // empty' "$vercel_config" 2>/dev/null)
  org_id=$(jq -r '.orgId // empty' "$vercel_config" 2>/dev/null)
  
  if [ -n "$project_id" ] && [ -z "${PROJECT_ID:-}" ]; then
    export PROJECT_ID="$project_id"
    log_info "Auto-detected PROJECT_ID: $project_id"
  fi
  
  if [ -n "$org_id" ] && [ -z "${TEAM_ID:-}" ]; then
    export TEAM_ID="$org_id"
    log_info "Auto-detected TEAM_ID: $org_id"
  fi
  
  return 0
}

# Fetch team slug after token is validated (requires API access)
resolve_team_slug() {
  # Skip if we already have a slug or no team ID
  if [ -n "${TEAM_SLUG:-}" ] || [ -z "${TEAM_ID:-}" ]; then
    return 0
  fi
  
  local slug
  slug=$(fetch_team_slug "$TEAM_ID")
  
  if [ -n "$slug" ]; then
    export TEAM_SLUG="$slug"
    log_info "Resolved TEAM_SLUG: $slug"
  fi
}

# Generate shell exports for environment setup
generate_env_exports() {
  local vercel_config="${1:-.vercel/project.json}"
  
  if [ ! -f "$vercel_config" ]; then
    echo "# Run 'vercel link' first to create .vercel/project.json"
    return 1
  fi
  
  local project_id
  local org_id
  project_id=$(jq -r '.projectId // empty' "$vercel_config" 2>/dev/null)
  org_id=$(jq -r '.orgId // empty' "$vercel_config" 2>/dev/null)
  
  echo "# Auto-generated from $vercel_config"
  echo "# Add these to your shell or .env file:"
  echo ""
  if [ -n "$project_id" ]; then
    echo "export PROJECT_ID=\"$project_id\""
  fi
  if [ -n "$org_id" ]; then
    echo "export TEAM_ID=\"$org_id\""
  fi
  echo ""
  echo "# Create a token at https://vercel.com/account/tokens"
  echo "# Required scopes: read:project, write:project"
  echo "export VERCEL_TOKEN=\"your-token-here\""
}

# =============================================================================
# API Functions
# =============================================================================

# Build team query parameters
# Some Vercel API endpoints work better with slug, others with teamId
# We include both when available for maximum compatibility
get_team_params() {
  local params=""
  
  if [ -n "${TEAM_ID:-}" ]; then
    params="teamId=${TEAM_ID}"
  fi
  
  if [ -n "${TEAM_SLUG:-}" ]; then
    if [ -n "$params" ]; then
      params="${params}&slug=${TEAM_SLUG}"
    else
      params="slug=${TEAM_SLUG}"
    fi
  fi
  
  echo "$params"
}

# Build query string with project and team
build_query_string() {
  local project_id="$1"
  local team_params
  team_params=$(get_team_params)
  
  if [ -n "$team_params" ]; then
    echo "?projectId=${project_id}&${team_params}"
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

# Get current firewall configuration
# Tries multiple endpoint formats for compatibility
get_firewall_config() {
  local project_id="$1"
  local query_string
  query_string=$(build_query_string "$project_id")
  
  log_info "Fetching current firewall configuration..."
  
  # Try the PATCH endpoint to get current config (returns config on success)
  # First, try to list IP rules which will tell us if firewall is accessible
  local response
  local http_code
  local body
  
  # Method 1: Try GET on the project's firewall config
  log_debug "Trying: GET /v1/security/firewall/config${query_string}"
  response=$(api_request "GET" "/v1/security/firewall/config${query_string}")
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -eq 200 ]; then
    echo "$body"
    return 0
  fi
  
  # Method 2: Try with explicit "active" as configVersion path parameter
  log_debug "Trying: GET /v1/security/firewall/config/active${query_string}"
  response=$(api_request "GET" "/v1/security/firewall/config/active${query_string}")
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  
  if [ "$http_code" -eq 200 ]; then
    echo "$body"
    return 0
  fi
  
  # Method 3: Try using slug instead of teamId if we have both
  if [ -n "${TEAM_ID:-}" ] && [ -n "${TEAM_SLUG:-}" ]; then
    local slug_query="?projectId=${project_id}&slug=${TEAM_SLUG}"
    log_debug "Trying with slug: GET /v1/security/firewall/config${slug_query}"
    response=$(api_request "GET" "/v1/security/firewall/config${slug_query}")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" -eq 200 ]; then
      echo "$body"
      return 0
    fi
  fi
  
  # All methods failed
  log_error "Failed to get firewall config (HTTP $http_code)"
  
  if [ "$http_code" -eq 404 ]; then
    log_error "Firewall config not found. Possible causes:"
    log_error "  - Project is not on Pro/Enterprise plan (Firewall requires Pro+)"
    log_error "  - Firewall is not enabled for this project"
    log_error "  - PROJECT_ID is incorrect: $project_id"
    log_error "  - TEAM_ID/TEAM_SLUG mismatch"
    log_error ""
    log_error "Try setting TEAM_SLUG manually (from your Vercel URL):"
    log_error "  export TEAM_SLUG=\"your-team-slug\""
  elif [ "$http_code" -eq 403 ]; then
    log_error "Access denied. Check token permissions (need read:project, write:project)."
  fi
  
  echo "$body" | jq '.' 2>/dev/null || echo "$body"
  return 1
}

# Find our managed allowlist rule(s) in the config
# Returns all matching rules (including chunked "Part X/Y" rules and duplicates)
find_allowlist_rules() {
  local config="$1"
  local rules=""
  
  log_debug "Searching for rules starting with name: $RULE_NAME"
  
  # Handle empty or invalid config
  if [ -z "$config" ] || [ "$config" = "{}" ] || [ "$config" = "null" ]; then
    log_debug "Config is empty, returning empty array"
    echo "[]"
    return 0
  fi
  
  # Match rules that exactly match our name OR start with our name (for "Part X/Y" suffix)
  # Structure 1: Nested under .active.rules (most common from API)
  rules=$(echo "$config" | jq -c --arg name "$RULE_NAME" '[.active.rules[]? | select(.name == $name or (.name | startswith($name + " (Part")))] // []' 2>/dev/null) || rules="[]"
  
  if [ -n "$rules" ] && [ "$rules" != "[]" ] && [ "$rules" != "null" ]; then
    log_debug "Found rules in .active.rules: $rules"
    echo "$rules"
    return 0
  fi
  
  # Structure 2: Direct .rules array
  rules=$(echo "$config" | jq -c --arg name "$RULE_NAME" '[.rules[]? | select(.name == $name or (.name | startswith($name + " (Part")))] // []' 2>/dev/null) || rules="[]"
  
  if [ -n "$rules" ] && [ "$rules" != "[]" ] && [ "$rules" != "null" ]; then
    log_debug "Found rules in .rules: $rules"
    echo "$rules"
    return 0
  fi
  
  log_debug "No matching rules found"
  echo "[]"
  return 0
}

# Find single allowlist rule (for backward compatibility)
find_allowlist_rule() {
  local config="$1"
  local rules
  rules=$(find_allowlist_rules "$config") || rules="[]"
  
  # Return the first rule if any exist
  local first_rule
  first_rule=$(echo "$rules" | jq -c '.[0] // empty' 2>/dev/null) || first_rule=""
  
  if [ -n "$first_rule" ] && [ "$first_rule" != "null" ]; then
    echo "$first_rule"
    return 0
  fi
  
  # Return empty string, not error (to avoid triggering set -e)
  echo ""
  return 0
}

# Remove all rules matching our name (cleanup duplicates)
cleanup_duplicate_rules() {
  local project_id="$1"
  local config="$2"
  
  local rules
  rules=$(find_allowlist_rules "$config")
  
  local rule_count
  rule_count=$(echo "$rules" | jq 'length' 2>/dev/null || echo "0")
  
  if [ "$rule_count" -le 1 ]; then
    # 0 or 1 rule is fine, no cleanup needed
    return 0
  fi
  
  log_warn "Found $rule_count duplicate rules. Cleaning up..."
  
  # Remove all rules (we'll insert a fresh one after)
  local query_string
  query_string=$(build_query_string "$project_id")
  
  echo "$rules" | jq -r '.[].id' | while read -r rule_id; do
    if [ -n "$rule_id" ] && [ "$rule_id" != "null" ]; then
      log_info "Removing duplicate rule: $rule_id"
      
      local request_body
      request_body=$(jq -n --arg id "$rule_id" '{action: "rules.remove", id: $id}')
      
      api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body" > /dev/null
      rate_limit_sleep
    fi
  done
  
  log_info "Cleanup complete"
}

# Create or update the allowlist rule
update_allowlist_rule() {
  local project_id="$1"
  local ips_json="$2"
  local action="$3"  # "insert" or "update"
  local existing_rule_id="${4:-}"
  local hostname="${RULE_HOSTNAME:-}"
  
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
  # For custom rules, 'action' must be an object with 'mitigate' containing the action
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
          action: "deny"
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

# Create or update the allowlist rule with a custom name (for chunked rules)
update_allowlist_rule_with_name() {
  local project_id="$1"
  local ips_json="$2"
  local action="$3"  # "insert" or "update"
  local existing_rule_id="${4:-}"
  local custom_name="${5:-$RULE_NAME}"
  local hostname="${RULE_HOSTNAME:-}"
  
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
  
  # Build the rule value with custom name
  local rule_value
  rule_value=$(jq -n \
    --arg name "$custom_name" \
    --arg description "$RULE_DESCRIPTION" \
    --argjson conditions "$conditions" \
    '{
      name: $name,
      description: $description,
      active: true,
      conditionGroup: [{conditions: $conditions}],
      action: {
        mitigate: {
          action: "deny"
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

# Remove the allowlist rule with retry logic
remove_allowlist_rule() {
  local project_id="$1"
  local rule_id="$2"
  local max_retries="${3:-3}"
  
  local query_string
  query_string=$(build_query_string "$project_id")
  
  local request_body
  request_body=$(jq -n \
    --arg id "$rule_id" \
    '{action: "rules.remove", id: $id}')
  
  local retry=0
  local delay=2
  
  while [ "$retry" -lt "$max_retries" ]; do
    local response
    response=$(api_request "PATCH" "/v1/security/firewall/config${query_string}" "$request_body")
    
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" -eq 200 ]; then
      return 0
    fi
    
    # Check for internal error - these are often transient
    local error_code
    error_code=$(echo "$body" | jq -r '.error.code // empty' 2>/dev/null)
    
    if [ "$error_code" = "FIREWALL_INTERNAL_ERROR" ]; then
      retry=$((retry + 1))
      if [ "$retry" -lt "$max_retries" ]; then
        log_warn "Vercel internal error removing rule $rule_id, retrying in ${delay}s... (attempt $((retry+1))/$max_retries)"
        sleep "$delay"
        delay=$((delay * 2))  # Exponential backoff
        continue
      fi
    fi
    
    log_error "Failed to remove rule $rule_id (HTTP $http_code)"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    return 1
  done
  
  log_error "Failed to remove rule $rule_id after $max_retries attempts"
  return 1
}


# =============================================================================
# CSV Parsing (Optimized)
# =============================================================================

# Fast inline IP validation using BASH_REMATCH (no subshells)
# Returns: 0 = valid IPv4, 1 = invalid, 2 = IPv6
validate_ip_fast() {
  local ip="$1"
  
  # Quick reject IPv6
  [[ "$ip" == *:* ]] && return 2
  
  # IPv4 regex check with CIDR support
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]] || return 1
  
  # Validate octets are <= 255 using BASH_REMATCH (no subprocess)
  (( BASH_REMATCH[1] <= 255 && BASH_REMATCH[2] <= 255 && 
     BASH_REMATCH[3] <= 255 && BASH_REMATCH[4] <= 255 )) || return 1
  
  return 0
}

# Parse CSV using awk for speed
# Handles: comments, header row, quoted fields, whitespace trimming
# Compatible with both BSD awk (macOS) and gawk (Linux)
parse_csv() {
  local csv_file="$1"
  local valid_ips=""
  local valid_count=0
  local error_count=0
  local line_num=0
  
  log_info "Parsing CSV file: $csv_file"
  
  # Use awk to extract IPs from CSV (handles quotes, skips comments/headers)
  # Uses FS=',' which works for standard CSVs (IP field won't contain commas)
  local extracted_ips
  extracted_ips=$(awk -F',' '
    # Skip empty lines and comments
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    
    # Process data lines
    NF > 0 {
      ip = $1
      # Remove surrounding quotes if present
      gsub(/^[[:space:]]*"?/, "", ip)
      gsub(/"?[[:space:]]*$/, "", ip)
      # Skip header row
      if (tolower(ip) == "ip") next
      # Skip empty
      if (ip == "") next
      # Output: line_number:ip
      print NR ":" ip
    }
  ' "$csv_file")
  
  # Validate each IP (fast inline validation)
  while IFS=':' read -r line_num ip; do
    [ -z "$ip" ] && continue
    
    local validation_result
    validate_ip_fast "$ip"
    validation_result=$?
    
    if [ $validation_result -eq 2 ]; then
      log_error "Line $line_num: IPv6 not supported - $ip"
      ((error_count++))
      continue
    elif [ $validation_result -eq 1 ]; then
      log_error "Line $line_num: Invalid IP format - $ip"
      ((error_count++))
      continue
    fi
    
    # Append to valid IPs (newline-separated)
    valid_ips+="${ip}"$'\n'
    ((valid_count++))
    
    log_debug "Line $line_num: $ip"
    
  done <<< "$extracted_ips"
  
  log_info "Parsed $valid_count valid IPs ($error_count errors)"
  
  if [ "$error_count" -gt 0 ]; then
    log_warn "Some IPs had validation errors. Review the errors above."
  fi
  
  # Convert to JSON array in a single jq call (fast!)
  if [ -n "$valid_ips" ]; then
    printf '%s' "$valid_ips" | jq -R -s 'split("\n") | map(select(length > 0))'
  else
    echo "[]"
  fi
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
  
  # Check for IP limit and offer optimization
  local needs_chunking=false
  local rules_needed=1
  
  if [ "$ip_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
    log_warn "IP count ($ip_count) exceeds limit ($MAX_IPS_PER_CONDITION per rule)"
    echo ""
    
    # Offer CIDR optimization
    if [ "${SKIP_OPTIMIZE:-false}" != "true" ]; then
      log_info "Attempting CIDR optimization to reduce IP count..."
      local optimized_json
      optimized_json=$(optimize_ip_list "$ips_json")
      local optimized_count
      optimized_count=$(echo "$optimized_json" | jq 'length')
      
      if [ "$optimized_count" -lt "$ip_count" ]; then
        local reduction=$((ip_count - optimized_count))
        log_info "CIDR optimization reduced entries from $ip_count to $optimized_count (-$reduction)"
        ips_json="$optimized_json"
        ip_count="$optimized_count"
      else
        log_info "No CIDR optimization possible (IPs are not contiguous)"
      fi
    fi
    
    # Check if we still need chunking
    if [ "$ip_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
      needs_chunking=true
      rules_needed=$(( (ip_count + MAX_IPS_PER_CONDITION - 1) / MAX_IPS_PER_CONDITION ))
      log_warn "Will create $rules_needed separate rules (max $MAX_IPS_PER_CONDITION IPs each)"
    fi
  fi
  
  echo ""
  log_info "Project ID: $project_id"
  [ -n "${TEAM_ID:-}" ] && log_info "Team ID: $TEAM_ID"
  log_info "IPs to allowlist: $ip_count"
  [ "$needs_chunking" = true ] && log_info "Rules to create: $rules_needed"
  log_info "Hostname scope: ${RULE_HOSTNAME:-project-wide}"
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
    if [ "$needs_chunking" = true ]; then
      echo "Would create $rules_needed allowlist rules with $ip_count total IPs."
    else
      echo "Would create/update allowlist rule with $ip_count IPs."
    fi
    echo "All traffic from IPs NOT in this list will be BLOCKED."
    echo ""
    echo "To apply changes, run without DRY_RUN=true"
    exit 0
  fi
  
  # Get current config
  local config
  config=$(get_firewall_config "$project_id")
  if [ $? -ne 0 ]; then
    # If we can't get config, assume no rules exist and proceed with insert
    log_warn "Could not fetch current config. Will attempt to create new rule."
    config="{}"
  fi
  
  log_debug "Firewall config response: $(echo "$config" | jq -c '.' 2>/dev/null || echo "$config")"
  
  # Check for existing rules and clean up
  local all_rules
  all_rules=$(find_allowlist_rules "$config")
  local existing_rule_count
  existing_rule_count=$(echo "$all_rules" | jq 'length' 2>/dev/null || echo "0")
  
  log_debug "Found $existing_rule_count existing rule(s) with our name"
  
  local action="insert"
  local existing_rule_id=""
  
  # For multi-rule scenarios, always clean up and recreate
  if [ "$needs_chunking" = true ] && [ "$existing_rule_count" -gt 0 ]; then
    log_info "Found $existing_rule_count existing rule(s). Will remove and recreate with new chunking."
    action="insert"
  elif [ "$existing_rule_count" -gt 1 ]; then
    # Multiple rules found - clean up duplicates
    log_warn "Found $existing_rule_count duplicate rules. Will clean up and create fresh rule."
    action="insert"
  elif [ "$existing_rule_count" -eq 1 ] && [ "$needs_chunking" = false ]; then
    # Single rule found and we only need one - update it
    local existing_rule
    existing_rule=$(echo "$all_rules" | jq -c '.[0]')
    existing_rule_id=$(echo "$existing_rule" | jq -r '.id')
    local existing_ip_count
    existing_ip_count=$(echo "$existing_rule" | jq '.conditionGroup[0].conditions[] | select(.type == "ip_address") | .value | length' 2>/dev/null || echo "0")
    
    log_info "Found existing allowlist rule (ID: $existing_rule_id)"
    log_info "Current IP count: $existing_ip_count"
    action="update"
  else
    log_info "No existing allowlist rule found. Will create new rule(s)."
  fi
  
  # Confirm
  echo ""
  echo "=============================================="
  echo "  WARNING"
  echo "=============================================="
  echo ""
  if [ "$needs_chunking" = true ]; then
    echo "This will CREATE $rules_needed allowlist rules."
    if [ "$existing_rule_count" -gt 0 ]; then
      echo "Existing rules will be REMOVED first."
    fi
  elif [ "$action" = "update" ]; then
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
  
  # Apply the rule(s)
  log_info "Applying allowlist rule(s)..."
  
  if [ "$needs_chunking" = true ]; then
    # Remove existing rules first (can be skipped with SKIP_REMOVAL=true)
    local removal_failures=0
    if [ "$existing_rule_count" -gt 0 ]; then
      if [ "${SKIP_REMOVAL:-false}" = "true" ]; then
        log_warn "SKIP_REMOVAL=true - Skipping removal of $existing_rule_count existing rule(s)"
        log_warn "You may have duplicate rules. Clean up manually in Vercel dashboard."
      else
        log_info "Removing $existing_rule_count existing rule(s)..."
        for rule_id in $(echo "$all_rules" | jq -r '.[].id'); do
          if remove_allowlist_rule "$project_id" "$rule_id" 3; then
            log_info "Removed rule: $rule_id"
          else
            log_warn "Failed to remove rule: $rule_id (will continue anyway)"
            ((removal_failures++))
          fi
          # Longer delay between removals to avoid rate limiting
          sleep 2
        done
        
        if [ "$removal_failures" -gt 0 ]; then
          log_warn "$removal_failures rule(s) could not be removed. You may need to remove them manually via Vercel dashboard."
          echo ""
          read -p "Continue creating new rules anyway? (yes/no): " CONTINUE
          if [ "$CONTINUE" != "yes" ]; then
            echo "Aborted."
            exit 1
          fi
        fi
      fi
    fi
    
    # Create chunked rules
    local chunk_start=0
    local chunk_num=1
    local success_count=0
    
    while [ "$chunk_start" -lt "$ip_count" ]; do
      local chunk_ips
      chunk_ips=$(echo "$ips_json" | jq ".[$chunk_start:$((chunk_start + MAX_IPS_PER_CONDITION))]")
      local chunk_size
      chunk_size=$(echo "$chunk_ips" | jq 'length')
      
      log_info "Creating rule $chunk_num/$rules_needed ($chunk_size IPs)..."
      
      # Create rule with part number in name
      local part_suffix=" (Part $chunk_num/$rules_needed)"
      if update_allowlist_rule_with_name "$project_id" "$chunk_ips" "insert" "" "${RULE_NAME}${part_suffix}"; then
        ((success_count++))
        log_debug "Rule $chunk_num created successfully"
      else
        log_error "Failed to create rule $chunk_num"
      fi
      
      chunk_start=$((chunk_start + MAX_IPS_PER_CONDITION))
      ((chunk_num++))
      rate_limit_sleep
    done
    
    if [ "$success_count" -eq "$rules_needed" ]; then
      echo ""
      echo "=============================================="
      echo "  SUCCESS"
      echo "=============================================="
      echo ""
      log_info "Created $success_count allowlist rules successfully!"
      log_info "Total whitelisted IPs: $ip_count"
      log_info "All other traffic will be BLOCKED."
      audit_log "ALLOWLIST_INSERT_CHUNKED" "ip_count=$ip_count rules=$success_count"
    else
      log_error "Only $success_count of $rules_needed rules were created"
      audit_log "ALLOWLIST_INSERT_CHUNKED_PARTIAL" "ip_count=$ip_count rules_created=$success_count rules_needed=$rules_needed"
      exit 1
    fi
  else
    # Single rule
    if update_allowlist_rule "$project_id" "$ips_json" "$action" "$existing_rule_id"; then
      echo ""
      echo "=============================================="
      echo "  SUCCESS"
      echo "=============================================="
      echo ""
      log_info "Allowlist rule ${action}ed successfully!"
      log_info "Whitelisted IPs: $ip_count"
      log_info "All other traffic will be BLOCKED."
      audit_log "ALLOWLIST_$(echo "$action" | tr '[:lower:]' '[:upper:]')" "ip_count=$ip_count"
    else
      log_error "Failed to $action allowlist rule"
      audit_log "ALLOWLIST_$(echo "$action" | tr '[:lower:]' '[:upper:]')_FAILED" "ip_count=$ip_count"
      exit 1
    fi
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

cmd_optimize() {
  local csv_file="$1"
  local output_file="${2:-}"
  
  if [ ! -f "$csv_file" ]; then
    log_error "CSV file not found: $csv_file"
    exit 1
  fi
  
  log_info "Analyzing IPs for CIDR optimization..."
  echo ""
  
  # Parse CSV to get IPs
  local ips_json
  ips_json=$(parse_csv "$csv_file")
  
  local original_count
  original_count=$(echo "$ips_json" | jq 'length')
  
  if [ "$original_count" -eq 0 ]; then
    log_error "No valid IPs found in CSV"
    exit 1
  fi
  
  log_info "Original IP count: $original_count"
  
  # Optimize IPs to CIDRs
  local optimized_json
  optimized_json=$(optimize_ip_list "$ips_json")
  
  local optimized_count
  optimized_count=$(echo "$optimized_json" | jq 'length')
  
  local reduction
  reduction=$((original_count - optimized_count))
  local reduction_pct
  if [ "$original_count" -gt 0 ]; then
    reduction_pct=$((reduction * 100 / original_count))
  else
    reduction_pct=0
  fi
  
  echo ""
  echo "=============================================="
  echo "  CIDR Optimization Results"
  echo "=============================================="
  echo ""
  echo "  Original entries:  $original_count"
  echo "  Optimized entries: $optimized_count"
  echo "  Reduction:         $reduction entries ($reduction_pct%)"
  echo ""
  
  # Check if we're still over the limit
  if [ "$optimized_count" -gt "$MAX_IPS_PER_CONDITION" ]; then
    local rules_needed=$(( (optimized_count + MAX_IPS_PER_CONDITION - 1) / MAX_IPS_PER_CONDITION ))
    log_warn "Still exceeds $MAX_IPS_PER_CONDITION per rule limit."
    log_warn "Will need $rules_needed separate rules when applying."
  else
    log_info "Optimized list fits within $MAX_IPS_PER_CONDITION limit!"
  fi
  
  echo ""
  
  # Show sample of optimized list
  log_info "Optimized entries (first 20):"
  echo "$optimized_json" | jq -r '.[0:20][]'
  
  local cidr_count
  cidr_count=$(echo "$optimized_json" | jq '[.[] | select(contains("/"))] | length')
  local single_count=$((optimized_count - cidr_count))
  
  echo ""
  log_info "CIDR ranges: $cidr_count, Individual IPs: $single_count"
  
  # Output to file if specified
  if [ -n "$output_file" ]; then
    echo ""
    log_info "Writing optimized list to: $output_file"
    
    # Write as CSV with comments
    {
      echo "# Optimized IP Allowlist"
      echo "# Generated from: $csv_file"
      echo "# Original: $original_count entries, Optimized: $optimized_count entries"
      echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
      echo "#"
      echo "# ip,vendor_name,notes"
      echo "$optimized_json" | jq -r '.[]' | while read -r entry; do
        echo "$entry,Optimized,Auto-aggregated CIDR"
      done
    } > "$output_file"
    
    log_info "Done! Use './vercel-ip-allowlist.sh apply $output_file' to apply."
  else
    echo ""
    log_info "To save optimized list, run:"
    echo "  $0 optimize $csv_file optimized-ips.csv"
  fi
}

cmd_setup() {
  local project_dir="${1:-$(pwd)}"
  
  echo ""
  echo "=============================================="
  echo "  Vercel IP Allowlist Setup"
  echo "=============================================="
  echo ""
  
  # Check for .vercel/project.json
  local vercel_config=""
  local dir="$project_dir"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/.vercel/project.json" ]; then
      vercel_config="$dir/.vercel/project.json"
      break
    fi
    dir=$(dirname "$dir")
  done
  
  if [ -z "$vercel_config" ]; then
    log_warn "No .vercel/project.json found in $project_dir or parent directories."
    echo ""
    echo "To enable auto-detection, run 'vercel link' in your project directory:"
    echo ""
    echo "  cd /path/to/your/vercel/project"
    echo "  vercel link"
    echo ""
    echo "Or set environment variables manually:"
    echo ""
    echo "  export VERCEL_TOKEN=\"your-token-here\"  # Required"
    echo "  export PROJECT_ID=\"prj_xxxxx\"          # Get from Vercel dashboard"
    echo "  export TEAM_ID=\"team_xxxxx\"            # Optional, for team projects"
    echo ""
    echo "Create a token at: https://vercel.com/account/tokens"
    echo "Required scopes: read:project, write:project"
    echo ""
    return 0
  fi
  
  log_info "Found Vercel config: $vercel_config"
  echo ""
  
  local project_id
  local org_id
  project_id=$(jq -r '.projectId // empty' "$vercel_config" 2>/dev/null)
  org_id=$(jq -r '.orgId // empty' "$vercel_config" 2>/dev/null)
  
  echo "Detected configuration:"
  [ -n "$project_id" ] && echo "  PROJECT_ID: $project_id"
  [ -n "$org_id" ] && echo "  TEAM_ID:    $org_id"
  echo ""
  
  echo "----------------------------------------------"
  echo "Setup Options:"
  echo "----------------------------------------------"
  echo ""
  echo "Option 1: Auto-detect (recommended)"
  echo ""
  echo "  The script auto-detects PROJECT_ID and TEAM_ID from .vercel/project.json."
  echo "  You only need to set VERCEL_TOKEN:"
  echo ""
  echo "  export VERCEL_TOKEN=\"your-token-here\""
  echo "  ./vercel-ip-allowlist.sh apply vendor-ips.csv"
  echo ""
  
  echo "Option 2: Export all variables"
  echo ""
  [ -n "$project_id" ] && echo "  export PROJECT_ID=\"$project_id\""
  [ -n "$org_id" ] && echo "  export TEAM_ID=\"$org_id\""
  echo "  export VERCEL_TOKEN=\"your-token-here\""
  echo ""
  
  echo "----------------------------------------------"
  echo ""
  echo "Create a token at: https://vercel.com/account/tokens"
  echo "Required scopes: read:project, write:project"
  echo ""
}

show_usage() {
  cat << EOF
Vercel IP Allowlist Script

DESCRIPTION:
  Creates a firewall rule that BLOCKS all traffic except from whitelisted IPs.
  This is different from bypass rules which only skip WAF checks.

USAGE:
  $0 setup                        Show environment setup instructions
  $0 apply <csv_file>             Create/update allowlist rule with IPs from CSV
  $0 optimize <csv_file> [output] Optimize IPs into CIDR ranges to reduce count
  $0 show                         Show current allowlist configuration
  $0 disable                      Disable the allowlist rule (keeps config)
  $0 remove                       Remove the allowlist rule entirely
  $0 backup                       Export current firewall configuration
  $0 --help                       Show this help message

OPTIONS:
  --projects-file <file>  File containing list of project IDs (one per line)
  --help                  Show this help message

ENVIRONMENT VARIABLES:
  VERCEL_TOKEN   (required) Vercel API token - create at https://vercel.com/account/tokens
  PROJECT_ID     (auto)     Auto-detected from .vercel/project.json, or set manually
  TEAM_ID        (auto)     Auto-detected from .vercel/project.json, or set manually
  TEAM_SLUG      (optional) Team slug (alternative to TEAM_ID)
  RULE_HOSTNAME  (optional) Hostname pattern for scoped rules (e.g., "api.crocs.com")
  DRY_RUN        (optional) Set to "true" for preview mode
  AUDIT_LOG      (optional) Path to audit log file
  DEBUG          (optional) Set to "true" for verbose output
  BACKUP_DIR     (optional) Directory for backups (default: ./backups)

  Note: PROJECT_ID and TEAM_ID are auto-detected from .vercel/project.json
        if you've run 'vercel link' in your project. Run '$0 setup' for help.

CSV FORMAT:
  ip,vendor_name,notes
  1.2.3.4,Acme Corp,Payment gateway
  5.6.7.0/24,Partner Inc,API integration

EXAMPLES:
  # First time setup
  cd /path/to/your/vercel/project
  vercel link                                    # Creates .vercel/project.json
  export VERCEL_TOKEN="your-token"               # Only token needed!
  /path/to/vercel-ip-allowlist.sh apply vendor-ips.csv

  # Preview changes (dry run)
  DRY_RUN=true ./vercel-ip-allowlist.sh apply vendor-ips.csv

  # Apply allowlist rule (auto-detects project from .vercel/project.json)
  ./vercel-ip-allowlist.sh apply vendor-ips.csv

  # Or specify project explicitly
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh apply vendor-ips.csv

  # Show current configuration
  ./vercel-ip-allowlist.sh show

  # Disable rule temporarily
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh disable

  # Remove rule completely
  PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh remove

  # Scope to specific hostname
  RULE_HOSTNAME="api.crocs.com" PROJECT_ID=prj_xxx ./vercel-ip-allowlist.sh apply vendor-ips.csv

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
  
  if [ $# -eq 0 ]; then
    show_usage
    exit 1
  fi
  
  local command="$1"
  shift
  
  # Setup command doesn't require token
  if [ "$command" = "setup" ]; then
    cmd_setup "$@"
    exit 0
  fi
  
  # Optimize command doesn't require token (local operation)
  if [ "$command" = "optimize" ]; then
    if [ -z "${1:-}" ]; then
      log_error "CSV file required"
      echo "Usage: $0 optimize <csv_file> [output_file.csv]"
      exit 1
    fi
    cmd_optimize "$1" "${2:-}"
    exit 0
  fi
  
  # Help doesn't require anything
  if [ "$command" = "--help" ] || [ "$command" = "-h" ]; then
    show_usage
    exit 0
  fi
  
  # Auto-detect PROJECT_ID and TEAM_ID from .vercel/project.json
  auto_detect_vercel_config "$(pwd)" 2>/dev/null || true
  
  # Check token for all other commands
  if [ -z "${VERCEL_TOKEN:-}" ]; then
    log_error "VERCEL_TOKEN environment variable is not set"
    echo ""
    echo "Create a token at: https://vercel.com/account/tokens"
    echo "Required scopes: read:project, write:project"
    echo ""
    echo "Run './vercel-ip-allowlist.sh setup' for more help."
    exit 1
  fi
  
  # Validate token once for all commands
  if ! validate_token; then
    exit 1
  fi
  
  # Resolve team slug from team ID (some API endpoints prefer slug)
  resolve_team_slug
  echo ""
  
  case "$command" in
    apply)
      if [ -z "${1:-}" ]; then
        log_error "CSV file required"
        echo "Usage: $0 apply <csv_file>"
        exit 1
      fi
      cmd_apply "$1"
      ;;
    show)
      cmd_show
      ;;
    disable)
      cmd_disable
      ;;
    remove)
      cmd_remove
      ;;
    backup)
      cmd_backup
      ;;
    *)
      log_error "Unknown command: $command"
      show_usage
      exit 1
      ;;
  esac
}

main "$@"
