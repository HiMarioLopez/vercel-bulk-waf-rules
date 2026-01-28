# Cloudflare IP Allowlist Export

The `exports/cloudflare-export.sh` script exports IP addresses from Cloudflare's IP Access Rules or IP Lists to a CSV format compatible with the Vercel allowlist script. This is particularly useful when migrating IP allowlists from Cloudflare to Vercel.

## Why Use This Script?

- **No UI Export**: Cloudflare doesn't provide a UI option to export IP Access Rules — the API is the only way
- **Handles Pagination**: Automatically fetches all pages for large IP lists (600+ IPs)
- **Vercel-Compatible Output**: Exports to CSV format that works directly with `vercel-bulk-waf-rules.sh`
- **Robust Error Handling**: Automatic retry with exponential backoff, rate limit handling
- **Debug Mode**: Verbose output for troubleshooting with `DEBUG=true`
- **Audit Logging**: Track all operations with `AUDIT_LOG` for compliance
- **Dry Run Mode**: Preview without making changes with `DRY_RUN=true`

## Prerequisites

### Dependencies

- `curl` - for API requests
- `jq` - for JSON parsing
- `bc` - for rate limiting calculations (optional, falls back to 1s delays)

**Install on macOS:**

```bash
brew install jq  # curl is pre-installed
```

**Install on Ubuntu/Debian:**

```bash
sudo apt-get install curl jq bc
```

### Cloudflare API Token

Create an API token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with one of these permissions:

| Export Type | Required Permission |
|-------------|---------------------|
| Account-level IP Access Rules | Account Firewall Access Rules Read |
| Zone-level IP Access Rules | Zone Firewall Access Rules Read (Firewall Services Read) |
| IP Lists | Account Rule Lists Read |

## Finding Your Account ID and Zone ID

### Account ID

1. Log into Cloudflare Dashboard
2. Click any domain
3. Scroll down in the right sidebar to find **Account ID**

Or via API:

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq '.result[] | {id, name}'
```

### Zone ID

1. Log into Cloudflare Dashboard
2. Click the domain you want
3. Scroll down in the right sidebar to find **Zone ID**

Or via API:

```bash
curl -s "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq '.result[] | {id, name}'
```

## Export Commands

### Export Account-Level IP Access Rules

Account-level rules apply to all zones in your account:

```bash
export CF_API_TOKEN="your-cloudflare-api-token"

# Export all whitelisted IPs (default)
./exports/cloudflare-export.sh --account abc123def456

# Export to a specific file
OUTPUT_FILE="vendor_ips.csv" ./exports/cloudflare-export.sh --account abc123def456

# Export blocked IPs instead
MODE_FILTER=block ./exports/cloudflare-export.sh --account abc123def456

# Export all modes (whitelist, block, challenge)
MODE_FILTER="" ./exports/cloudflare-export.sh --account abc123def456
```

### Export Zone-Level IP Access Rules

Zone-level rules apply only to a specific domain:

```bash
export CF_API_TOKEN="your-cloudflare-api-token"

# Export whitelisted IPs for a specific zone
./exports/cloudflare-export.sh --zone xyz789abc123

# Export to specific file
OUTPUT_FILE="zone_ips.csv" ./exports/cloudflare-export.sh --zone xyz789abc123
```

### Export from IP Lists

IP Lists are reusable lists that can be referenced in custom rules:

```bash
export CF_API_TOKEN="your-cloudflare-api-token"

# First, list all IP Lists in your account
./exports/cloudflare-export.sh --all-lists abc123def456

# Then export a specific list by ID
./exports/cloudflare-export.sh --list abc123def456 list_id_here

# Export to specific file
OUTPUT_FILE="ip_list.csv" ./exports/cloudflare-export.sh --list abc123def456 list_id_here
```

## Output Format

The script outputs CSV with these columns:

```csv
ip,notes,mode,created_on
"192.168.1.1","Office IP","whitelist","2024-01-15T10:30:00Z"
"10.0.0.0/8","Internal network","whitelist","2024-01-15T10:31:00Z"
```

This format is directly compatible with `vercel-bulk-waf-rules.sh`.

## API Endpoints Used

| Operation | Endpoint |
|-----------|----------|
| List account IP Access Rules | `GET /accounts/{account_id}/firewall/access_rules/rules` |
| List zone IP Access Rules | `GET /zones/{zone_id}/firewall/access_rules/rules` |
| List all IP Lists | `GET /accounts/{account_id}/rules/lists` |
| Get IP List items | `GET /accounts/{account_id}/rules/lists/{list_id}/items` |

All endpoints use the base URL: `https://api.cloudflare.com/client/v4/`

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CF_API_TOKEN` | Yes | - | Cloudflare API token |
| `OUTPUT_FILE` | No | `cloudflare_ips.csv` | Output CSV file path |
| `MODE_FILTER` | No | `whitelist` | Filter by mode: `whitelist`, `block`, `challenge`, or empty for all |
| `DRY_RUN` | No | `false` | Set to `true` to preview without making changes |
| `DEBUG` | No | `false` | Set to `true` for verbose debug output |
| `AUDIT_LOG` | No | - | Path to audit log file for tracking operations |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Missing dependencies (curl, jq) |
| 2 | Missing CF_API_TOKEN |
| 3 | Invalid or expired token |
| 4 | API error (non-retryable) |
| 5 | Rate limited (after max retries) |
| 6 | Invalid arguments |
| 7 | File I/O error |
| 8 | Network error |

## Migration Workflow

Complete workflow to migrate from Cloudflare to Vercel:

```bash
# Step 1: Set up Cloudflare token
export CF_API_TOKEN="your-cloudflare-token"

# Step 2: Export IPs from Cloudflare
./exports/cloudflare-export.sh --account abc123def456
# Creates: cloudflare_ips.csv

# Step 3: Set up Vercel token (in your Vercel project directory)
export VERCEL_TOKEN="your-vercel-token"

# Step 4: Preview what will be applied
DRY_RUN=true ./vercel-bulk-waf-rules.sh apply cloudflare_ips.csv

# Step 5: Apply to Vercel
RULE_MODE=bypass ./vercel-bulk-waf-rules.sh apply cloudflare_ips.csv
```

## Debugging

The script includes comprehensive debugging capabilities:

```bash
# Enable debug mode for verbose output
DEBUG=true ./exports/cloudflare-export.sh --account abc123def456

# Enable audit logging to track all operations
AUDIT_LOG="./cf-export.log" ./exports/cloudflare-export.sh --account abc123def456

# Combine both for full visibility
DEBUG=true AUDIT_LOG="./cf-export.log" ./exports/cloudflare-export.sh --account abc123def456

# Dry run to preview without writing files
DRY_RUN=true ./exports/cloudflare-export.sh --account abc123def456
```

**Debug mode shows:**

- Full API response bodies
- HTTP status codes
- Rate limit headers
- Token verification details
- Pagination progress

**Audit log records:**

- Timestamp of each operation
- User who ran the script
- Success/failure status
- Error codes and messages
- Export statistics

## Error Handling

The script includes robust error handling:

- **Automatic Retries**: Retries failed requests up to 3 times with exponential backoff
- **Rate Limit Handling**: Automatically waits when hitting Cloudflare's rate limits (1,200 req/5min)
- **Token Verification**: Validates token before starting export
- **TLS Security**: All API calls use verified TLS 1.2+ connections
- **Detailed Error Messages**: Displays Cloudflare error codes and messages for debugging

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `CF_API_TOKEN environment variable is not set` | Token not exported | Run `export CF_API_TOKEN="your-token"` |
| `CF_API_TOKEN appears malformed` | Token has invalid characters | Check token was copied correctly |
| `Token verification failed (HTTP 400)` | Invalid token format | Create a new token at Cloudflare dashboard |
| `Token verification failed (HTTP 401)` | Expired or invalid token | Create a new token |
| `Token status: expired` | Token has expired | Create a new token |
| `HTTP 403` | Insufficient permissions | Check token has "Firewall Access Rules Read" permission |
| `HTTP 404` | Invalid account/zone/list ID | Verify the ID is correct |
| `HTTP 429` | Rate limited | Script auto-retries; if persistent, wait a few minutes |
| `Network error` | Connection failed | Check internet connection and firewall settings |
| `jq: command not found` | jq not installed | Install with `brew install jq` or `apt install jq` |
| `Exit code 5` | Rate limited after max retries | Wait 5 minutes and try again |

**Debugging Tips:**

1. **Enable debug mode**: `DEBUG=true ./exports/cloudflare-export.sh --account xxx`
2. **Check audit log**: `AUDIT_LOG="./debug.log" ./exports/cloudflare-export.sh --account xxx`
3. **Test token manually**:

   ```bash
   curl -s "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer $CF_API_TOKEN" | jq
   ```

## IP Access Rules vs IP Lists

Cloudflare has two ways to manage IP allowlists:

| Feature | IP Access Rules | IP Lists |
|---------|-----------------|----------|
| Scope | Account or Zone level | Account level |
| Action | Direct (whitelist/block/challenge) | Referenced in custom rules |
| UI Location | Security → WAF → Tools | Manage Account → Configurations → Lists |
| Best for | Simple allow/block rules | Complex rules, multiple conditions |

Use `--account` or `--zone` for IP Access Rules, use `--list` for IP Lists.
