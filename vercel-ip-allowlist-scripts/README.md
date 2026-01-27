# Vercel IP Allowlist - Firewall Rules for Whitelisted IPs

Automation scripts to create IP allowlist rules in Vercel Firewall with **two modes**:

| Mode | Description | Use Case |
|------|-------------|----------|
| **deny** | Block all traffic EXCEPT from whitelisted IPs | Private apps, vendor-only access |
| **bypass** | Bypass WAF/security for whitelisted IPs | Public apps with vendor integrations (webhooks, scanners, bots) |

## Quick Start

### 1. Set Up Environment

**Option A: Auto-detect from Vercel CLI (recommended)**

If you've already linked your project with the Vercel CLI, the script auto-detects `PROJECT_ID` and `TEAM_ID`:

```bash
# In your Vercel project directory (where you ran 'vercel link')
cd /path/to/your/vercel/project

# Only the token is required - project info is auto-detected from .vercel/project.json
export VERCEL_TOKEN="your-vercel-api-token"
```

**Option B: Manual setup**

```bash
export VERCEL_TOKEN="your-vercel-api-token"
export PROJECT_ID="prj_xxxxxxxxxxxx"
export TEAM_ID="team_xxxxxxxxxxxx"  # Optional, for team projects
```

**Need help?** Run `./vercel-ip-allowlist.sh setup` for guided setup instructions.

### 2. Create IP Whitelist CSV

```csv
ip,vendor_name,notes
1.2.3.4,Acme Corp,Payment gateway
5.6.7.0/24,Partner Inc,API integration
10.20.30.40,Office,Main office egress
```

### 3. Preview Changes (Dry Run)

```bash
DRY_RUN=true ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

### 4. Apply Allowlist

**Interactive Mode (recommended for first-time setup):**

```bash
./vercel-ip-allowlist.sh apply vendor-ips.csv
```

The script will prompt you to choose your intended behavior:

```
Select rule mode:

  1) allowlist  - Block ALL traffic except listed IPs
                  Use for: Private apps, vendor-only access

  2) bypass     - Bypass WAF for listed IPs, allow all other traffic
                  Use for: Public apps with vendor integrations

Enter choice [1-2]:
```

**Explicit Mode (for CI/CD or scripting):**

```bash
# Deny mode - Block all except allowlisted IPs
RULE_MODE=deny ./vercel-ip-allowlist.sh apply vendor-ips.csv

# Bypass mode - Bypass WAF for allowlisted IPs
RULE_MODE=bypass ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

> **Note:** In non-interactive environments (CI/CD), you must set `RULE_MODE` explicitly or the script will exit with an error.

## Commands

| Command | Description |
|---------|-------------|
| `./vercel-ip-allowlist.sh setup` | Show environment setup instructions |
| `./vercel-ip-allowlist.sh apply <csv>` | Create/update allowlist rule |
| `./vercel-ip-allowlist.sh show` | Show current allowlist configuration |
| `./vercel-ip-allowlist.sh disable` | Disable rule (allows all traffic temporarily) |
| `./vercel-ip-allowlist.sh remove` | Remove rule entirely |
| `./vercel-ip-allowlist.sh backup` | Export current firewall config |

## How It Works

This tool creates a **custom firewall rule** with behavior based on the selected mode:

### Deny Mode (default)

1. Uses the `ninc` (NOT IN) operator to match IPs **not** in your whitelist
2. Applies a `deny` action to block those IPs
3. Rule name: `IP Allowlist - Auto-managed`

### Bypass Mode

1. Uses the `inc` (IN) operator to match IPs **in** your whitelist
2. Applies a `bypass` action to skip WAF/security checks
3. Rule name: `IP Bypass - Auto-managed`

Both modes support updating the rule in place as your IP list changes.

### API Under the Hood (Deny Mode)

```json
{
  "action": "rules.insert",
  "value": {
    "name": "IP Allowlist - Auto-managed",
    "active": true,
    "conditionGroup": [{
      "conditions": [{
        "type": "ip_address",
        "op": "ninc",
        "value": ["1.2.3.4", "5.6.7.0/24"]
      }]
    }],
    "action": {
      "mitigate": {
        "action": "deny"
      }
    }
  }
}
```

## Scripts

| Script | Purpose |
|--------|---------|
| `vercel-ip-allowlist.sh` | Main script for IP allowlisting |
| `rollback.sh` | Backup, restore, enable/disable allowlist rules |
| `cloudflare-export.sh` | Export IPs from Cloudflare WAF rules (useful for migration) |
| `vendor-ips.csv` | Template CSV file |

## Vercel Credentials Setup

This section explains how to get the credentials needed to run the Vercel IP allowlist scripts.

### Prerequisites

**Dependencies:**

- `curl` - for API requests
- `jq` - for JSON parsing
- `bc` - for calculations (usually pre-installed)

Install on macOS:

```bash
brew install jq
```

Install on Ubuntu/Debian:

```bash
sudo apt-get install jq bc
```

### Creating a Vercel API Token

1. Go to [vercel.com/account/tokens](https://vercel.com/account/tokens)
   - Make sure you're under **Personal Account** (not Teams) in the top-left dropdown
2. Click **Create** to open the token creation modal
3. Enter a descriptive name (e.g., "IP Allowlist Script")
4. Click **Create Token**
5. **Choose the scope** from the dropdown:
   - Select your **Personal Account** for personal projects
   - Select a **specific Team** for team projects
6. **Copy the token immediately** — it will not be shown again

```bash
export VERCEL_TOKEN="your-token-here"
```

### Required Token Permissions

Your token needs these permissions based on how you created it:

| Scope | Required For | Description |
|-------|--------------|-------------|
| Personal Account | Personal projects | Full access to your personal projects |
| Team Scope | Team projects | Access to projects within that team |

> **Note:** Vercel tokens inherit permissions based on your account role. If you're a team member, your token can access team resources you have permission to modify.

### Finding Your Project ID

**Method 1: From the Vercel Dashboard**

1. Go to [vercel.com/dashboard](https://vercel.com/dashboard)
2. Click on your project
3. Go to **Settings** → **General**
4. Scroll down to find **Project ID** (starts with `prj_`)

**Method 2: From `.vercel/project.json` (Recommended)**

If you've run `vercel link` in your project directory:

```bash
cat .vercel/project.json
```

Output:

```json
{
  "projectId": "prj_xxxxxxxxxxxxxxxxxxxx",
  "orgId": "team_xxxxxxxxxxxxxxxxxxxx"
}
```

The script **automatically reads this file** if you run it from your project directory.

**Method 3: From the URL**

When viewing your project in the dashboard, the URL contains the project name:

```
https://vercel.com/your-team/your-project-name/settings
```

You can use the project name instead of the ID with the API.

**Method 4: Via API**

```bash
# List all projects
curl -s "https://api.vercel.com/v9/projects" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '.projects[] | {id, name}'

# For team projects, add teamId
curl -s "https://api.vercel.com/v9/projects?teamId=team_xxx" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '.projects[] | {id, name}'
```

### Finding Your Team ID

**Method 1: From the Dashboard**

1. Click your team name in the top-left dropdown
2. Go to **Settings** → **General**
3. Scroll down to **Team ID** (starts with `team_`)

Or navigate directly to:

```
https://vercel.com/teams/your-team-name/settings
```

**Method 2: From `.vercel/project.json`**

```bash
cat .vercel/project.json | jq '.orgId'
```

The `orgId` field is your Team ID (for team projects) or your user ID (for personal projects).

**Method 3: Via API**

```bash
curl -s "https://api.vercel.com/v2/teams" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '.teams[] | {id, name, slug}'
```

### Quick Setup Summary

**Option A: Auto-detect (Recommended)**

If you've already linked your project with Vercel CLI:

```bash
cd /path/to/your/vercel/project  # Directory with .vercel/project.json
export VERCEL_TOKEN="your-token"
./vercel-ip-allowlist.sh apply vendor-ips.csv
```

**Option B: Manual Setup**

```bash
export VERCEL_TOKEN="your-token"
export PROJECT_ID="prj_xxxxxxxxxxxx"
export TEAM_ID="team_xxxxxxxxxxxx"  # Only for team projects
./vercel-ip-allowlist.sh apply vendor-ips.csv
```

**Option C: Guided Setup**

```bash
./vercel-ip-allowlist.sh setup
```

### Verifying Your Credentials

Test that your credentials work:

```bash
# Test token validity
curl -s "https://api.vercel.com/v2/user" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '{username, email}'

# Test project access
curl -s "https://api.vercel.com/v9/projects/$PROJECT_ID?teamId=$TEAM_ID" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '{id, name}'

# Or use the script's show command
./vercel-ip-allowlist.sh show
```

### Troubleshooting Vercel Credentials

| Error | Cause | Solution |
|-------|-------|----------|
| `VERCEL_TOKEN environment variable is not set` | Token not exported | Run `export VERCEL_TOKEN="your-token"` |
| `HTTP 401 Unauthorized` | Invalid or expired token | Create a new token at vercel.com/account/tokens |
| `HTTP 403 Forbidden` | Token lacks team access | Recreate token with correct team scope |
| `HTTP 404 Not Found` | Wrong PROJECT_ID or TEAM_ID | Verify IDs from dashboard or `.vercel/project.json` |
| `Project not found` | Missing TEAM_ID for team project | Add `export TEAM_ID="team_xxx"` |

### Token Security Best Practices

- **Never commit tokens** to version control
- **Use environment variables** or a secrets manager
- **Scope tokens minimally** — use team-specific tokens when possible
- **Rotate tokens regularly** — especially after team member departures
- **Use short-lived tokens** for CI/CD when possible

For CI/CD, store tokens as secrets:

- **GitHub Actions**: Repository Settings → Secrets → `VERCEL_TOKEN`
- **GitLab CI**: Settings → CI/CD → Variables → `VERCEL_TOKEN`
- **CircleCI**: Project Settings → Environment Variables

---

## Cloudflare IP Export Script

The `cloudflare-export.sh` script exports IP addresses from Cloudflare's IP Access Rules or IP Lists to a CSV format compatible with the Vercel allowlist script. This is particularly useful when migrating IP allowlists from Cloudflare to Vercel.

### Why Use This Script?

- **No UI Export**: Cloudflare doesn't provide a UI option to export IP Access Rules — the API is the only way
- **Handles Pagination**: Automatically fetches all pages for large IP lists (600+ IPs)
- **Vercel-Compatible Output**: Exports to CSV format that works directly with `vercel-ip-allowlist.sh`
- **Robust Error Handling**: Automatic retry with exponential backoff, rate limit handling
- **Debug Mode**: Verbose output for troubleshooting with `DEBUG=true`
- **Audit Logging**: Track all operations with `AUDIT_LOG` for compliance
- **Dry Run Mode**: Preview without making changes with `DRY_RUN=true`

### Prerequisites

**Dependencies:**

- `curl` - for API requests
- `jq` - for JSON parsing
- `bc` - for rate limiting calculations (optional, falls back to 1s delays)

**Cloudflare API Token:**

Create an API token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with one of these permissions:

| Export Type | Required Permission |
|-------------|---------------------|
| Account-level IP Access Rules | Account Firewall Access Rules Read |
| Zone-level IP Access Rules | Zone Firewall Access Rules Read (Firewall Services Read) |
| IP Lists | Account Rule Lists Read |

### Finding Your Account ID and Zone ID

**Account ID:**

1. Log into Cloudflare Dashboard
2. Click any domain
3. Scroll down in the right sidebar to find **Account ID**

Or via API:

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq '.result[] | {id, name}'
```

**Zone ID:**

1. Log into Cloudflare Dashboard
2. Click the domain you want
3. Scroll down in the right sidebar to find **Zone ID**

Or via API:

```bash
curl -s "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq '.result[] | {id, name}'
```

### Export Commands

#### 1. Export Account-Level IP Access Rules

Account-level rules apply to all zones in your account:

```bash
export CF_API_TOKEN="your-cloudflare-api-token"

# Export all whitelisted IPs (default)
./cloudflare-export.sh --account abc123def456

# Export to a specific file
OUTPUT_FILE="vendor_ips.csv" ./cloudflare-export.sh --account abc123def456

# Export blocked IPs instead
MODE_FILTER=block ./cloudflare-export.sh --account abc123def456

# Export all modes (whitelist, block, challenge)
MODE_FILTER="" ./cloudflare-export.sh --account abc123def456
```

#### 2. Export Zone-Level IP Access Rules

Zone-level rules apply only to a specific domain:

```bash
export CF_API_TOKEN="your-cloudflare-api-token"

# Export whitelisted IPs for a specific zone
./cloudflare-export.sh --zone xyz789abc123

# Export to specific file
OUTPUT_FILE="zone_ips.csv" ./cloudflare-export.sh --zone xyz789abc123
```

#### 3. Export from IP Lists

IP Lists are reusable lists that can be referenced in custom rules:

```bash
export CF_API_TOKEN="your-cloudflare-api-token"

# First, list all IP Lists in your account
./cloudflare-export.sh --all-lists abc123def456

# Then export a specific list by ID
./cloudflare-export.sh --list abc123def456 list_id_here

# Export to specific file
OUTPUT_FILE="ip_list.csv" ./cloudflare-export.sh --list abc123def456 list_id_here
```

### Output Format

The script outputs CSV with these columns:

```csv
ip,notes,mode,created_on
"192.168.1.1","Office IP","whitelist","2024-01-15T10:30:00Z"
"10.0.0.0/8","Internal network","whitelist","2024-01-15T10:31:00Z"
```

This format is directly compatible with `vercel-ip-allowlist.sh`.

### API Endpoints Used

The script uses these Cloudflare API v4 endpoints:

| Operation | Endpoint |
|-----------|----------|
| List account IP Access Rules | `GET /accounts/{account_id}/firewall/access_rules/rules` |
| List zone IP Access Rules | `GET /zones/{zone_id}/firewall/access_rules/rules` |
| List all IP Lists | `GET /accounts/{account_id}/rules/lists` |
| Get IP List items | `GET /accounts/{account_id}/rules/lists/{list_id}/items` |

All endpoints use the base URL: `https://api.cloudflare.com/client/v4/`

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CF_API_TOKEN` | Yes | - | Cloudflare API token |
| `OUTPUT_FILE` | No | `cloudflare_ips.csv` | Output CSV file path |
| `MODE_FILTER` | No | `whitelist` | Filter by mode: `whitelist`, `block`, `challenge`, or empty for all |
| `DRY_RUN` | No | `false` | Set to `true` to preview without making changes |
| `DEBUG` | No | `false` | Set to `true` for verbose debug output |
| `AUDIT_LOG` | No | - | Path to audit log file for tracking operations |

### Exit Codes

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

### Example: Complete Migration Workflow

```bash
# Step 1: Set up Cloudflare token
export CF_API_TOKEN="your-cloudflare-token"

# Step 2: Export IPs from Cloudflare
./cloudflare-export.sh --account abc123def456
# Creates: cloudflare_ips.csv

# Step 3: Set up Vercel token (in your Vercel project directory)
export VERCEL_TOKEN="your-vercel-token"

# Step 4: Preview what will be applied
DRY_RUN=true ./vercel-ip-allowlist.sh apply cloudflare_ips.csv

# Step 5: Apply to Vercel
./vercel-ip-allowlist.sh apply cloudflare_ips.csv
```

### Debugging Cloudflare Export

The script includes comprehensive debugging capabilities for troubleshooting:

```bash
# Enable debug mode for verbose output
DEBUG=true ./cloudflare-export.sh --account abc123def456

# Enable audit logging to track all operations
AUDIT_LOG="./cf-export.log" ./cloudflare-export.sh --account abc123def456

# Combine both for full visibility
DEBUG=true AUDIT_LOG="./cf-export.log" ./cloudflare-export.sh --account abc123def456

# Dry run to preview without writing files
DRY_RUN=true ./cloudflare-export.sh --account abc123def456
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

### Error Handling

The script includes robust error handling:

- **Automatic Retries**: Retries failed requests up to 3 times with exponential backoff
- **Rate Limit Handling**: Automatically waits when hitting Cloudflare's rate limits (1,200 req/5min)
- **Token Verification**: Validates token before starting export
- **TLS Security**: All API calls use verified TLS 1.2+ connections
- **Detailed Error Messages**: Displays Cloudflare error codes and messages for debugging

### Troubleshooting Cloudflare Export

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

1. **Enable debug mode**: `DEBUG=true ./cloudflare-export.sh --account xxx`
2. **Check audit log**: `AUDIT_LOG="./debug.log" ./cloudflare-export.sh --account xxx`
3. **Test token manually**:
   ```bash
   curl -s "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer $CF_API_TOKEN" | jq
   ```

### IP Access Rules vs IP Lists

Cloudflare has two ways to manage IP allowlists:

| Feature | IP Access Rules | IP Lists |
|---------|-----------------|----------|
| Scope | Account or Zone level | Account level |
| Action | Direct (whitelist/block/challenge) | Referenced in custom rules |
| UI Location | Security → WAF → Tools | Manage Account → Configurations → Lists |
| Best for | Simple allow/block rules | Complex rules, multiple conditions |

Use `--account` or `--zone` for IP Access Rules, use `--list` for IP Lists.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VERCEL_TOKEN` | Yes | Vercel API token with read:project, write:project scopes |
| `PROJECT_ID` | Auto | Auto-detected from `.vercel/project.json`, or set manually |
| `TEAM_ID` | Auto | Auto-detected from `.vercel/project.json`, or set manually |
| `TEAM_SLUG` | No | Team slug (alternative to TEAM_ID) |
| `RULE_MODE` | No* | `deny` or `bypass` - see modes and interactive selection below |
| `RULE_HOSTNAME` | No | Scope rule to specific hostname (e.g., "api.crocs.com") |
| `DRY_RUN` | No | Set to "true" for preview mode |
| `AUDIT_LOG` | No | Path to audit log file |
| `DEBUG` | No | Set to "true" for verbose output |
| `BACKUP_DIR` | No | Backup directory (default: ./backups) |

> **Note:** If you've run `vercel link` in your project, `PROJECT_ID` and `TEAM_ID` are automatically detected from `.vercel/project.json`. You only need to set `VERCEL_TOKEN`.

## Rule Mode Selection

The script supports two rule modes and will prompt you to select one if not specified:

### Interactive Mode (Terminal)

When running interactively in a terminal, if `RULE_MODE` is not set, you'll see a prompt:

```
$ ./vercel-ip-allowlist.sh apply vendor-ips.csv

Select rule mode:

  1) allowlist  - Block ALL traffic except listed IPs
                  Use for: Private apps, vendor-only access

  2) bypass     - Bypass WAF for listed IPs, allow all other traffic
                  Use for: Public apps with vendor integrations

Enter choice [1-2]: 
```

### CI/CD (Non-Interactive)

In non-interactive environments (CI/CD pipelines), `RULE_MODE` must be set explicitly:

```bash
# GitHub Actions, GitLab CI, etc.
RULE_MODE=bypass ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

If `RULE_MODE` is not set in CI/CD, the script will error with instructions.

### Setting Mode Explicitly

You can always skip the prompt by setting `RULE_MODE`:

```bash
# Allowlist mode (block all except listed IPs)
RULE_MODE=deny ./vercel-ip-allowlist.sh apply vendor-ips.csv

# Bypass mode (bypass WAF for listed IPs)
RULE_MODE=bypass ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

## CSV Format

```csv
ip,vendor_name,notes
1.2.3.4,Acme Corp,Payment gateway
5.6.7.0/24,Partner Inc,API integration
10.20.30.40,Analytics Co,Tracking service
```

- `ip` (required): IPv4 address or CIDR range
- `vendor_name` (optional): Vendor name for tracking
- `notes` (optional): Additional notes

> **Note:** Only IPv4 is supported. IPv6 addresses will be rejected.

### CSV Escaping Rules

The script follows RFC 4180 CSV conventions:

| Scenario | How to Handle | Example |
|----------|---------------|---------|
| Field contains comma | Wrap in double quotes | `"Acme, Inc"` |
| Field contains double quote | Wrap in quotes, double the quote | `"Company ""Quoted"""` |
| Field contains newline | Wrap in double quotes | `"Line1\nLine2"` |
| Field contains single quote | No escaping needed | `Mario's Shop` or `"Mario's Shop"` |
| Simple text | No quotes needed | `Acme Corp` |

**Examples:**

```csv
# Simple fields - no quotes needed
1.2.3.4,Acme Corp,Payment gateway

# Comma in field - wrap in quotes
5.6.7.0/24,"Acme, Inc",Vendor name has comma

# Double quotes in field - wrap and double them
10.20.30.40,"Company ""Best""",Name with quotes

# Single quotes - no special handling needed
192.168.1.100,Mario's Shop,Single quotes are fine

# Mixed - only quote fields that need it
203.0.113.50,"O'Brien, Ltd",Irish vendor with comma
```

## Hostname Scoping

By default, the allowlist applies to your entire project. To scope to a specific hostname:

```bash
RULE_HOSTNAME="api.crocs.com" ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

This is useful when you want to:

- Restrict API access to specific IPs while keeping the frontend open
- Apply different allowlists to different subdomains

## Rollback Operations

### Create Backup

```bash
PROJECT_ID=prj_xxx ./rollback.sh backup
# Creates: backups/backup-prj_xxx-20260126-143000.json
```

### Show Current State

```bash
PROJECT_ID=prj_xxx ./rollback.sh show
```

### Disable Temporarily

```bash
# Disable rule (allows all traffic) but keeps configuration
PROJECT_ID=prj_xxx ./rollback.sh disable

# Re-enable later
PROJECT_ID=prj_xxx ./rollback.sh enable
```

### Restore from Backup

```bash
PROJECT_ID=prj_xxx ./rollback.sh restore backups/backup-prj_xxx-20260126-143000.json
```

### Remove Completely

```bash
PROJECT_ID=prj_xxx ./rollback.sh remove
# Creates automatic backup before deletion
```

## API Token Requirements

See the [Vercel Credentials Setup](#vercel-credentials-setup) section for detailed instructions on creating an API token and finding your Project ID and Team ID.

**Quick reference:** Create a token at [vercel.com/account/tokens](https://vercel.com/account/tokens) and ensure it has access to the team/account containing your project.

## IP Limits

Vercel may have limits on the number of IPs per condition (typically 75). For large IP lists:

- The script warns if you exceed the recommended limit
- Consider grouping IPs into CIDR ranges where possible
- Contact Vercel support for higher limits if needed

## Best Practices

### Before Applying

1. **Backup First**: Run `./rollback.sh backup` before making changes
2. **Dry Run**: Always preview with `DRY_RUN=true`
3. **Test on Non-Production**: Test on a staging project first
4. **Include Your IP**: Make sure to include your office/VPN IPs!

### Security

- Store tokens in a secrets manager, not in env files
- Use project-scoped tokens when possible
- Enable `AUDIT_LOG` for compliance tracking
- Review allowlist regularly to remove stale entries

### Common Mistakes

| Mistake | Consequence | Prevention |
|---------|-------------|------------|
| Forgetting your own IP | Lock yourself out | Always include office/VPN IPs |
| Applying to wrong project | Wrong app blocked | Double-check PROJECT_ID |
| Not testing dry run | Unexpected blocking | Always run dry run first |

## Troubleshooting

### "I locked myself out!"

1. Use Vercel Dashboard to disable the rule:
   - Go to Project → Settings → Security → Firewall
   - Find the "IP Allowlist - Auto-managed" rule
   - Toggle it off or delete it

2. Or use the API from a whitelisted IP:

   ```bash
   PROJECT_ID=prj_xxx ./rollback.sh disable
   ```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `IPv6 not supported` | IPv6 in CSV | Use IPv4 only |
| `HTTP 403` | Insufficient permissions | Check token scopes |
| `HTTP 404` | Project not found | Verify PROJECT_ID |
| `No allowlist rule found` | Rule doesn't exist | Run `apply` first |

## CI/CD Integration

> **Important:** In CI/CD (non-interactive) environments, `RULE_MODE` must be set explicitly. The script will not prompt and will error if the mode is not specified.

### GitHub Actions

See [`examples/github-action.yml`](examples/github-action.yml) for a complete workflow that:

- Validates configurations on pull requests
- Applies changes on merge to main
- Supports manual dry-run triggers

**Setup:**

1. Add secrets: `VERCEL_TOKEN`
2. Add variables: `VERCEL_PROJECT_ID`, `VERCEL_TEAM_ID` (optional), `RULE_MODE` (required)
3. Copy the workflow file to `.github/workflows/`

### GitLab CI

```yaml
stages:
  - validate
  - deploy

validate:
  stage: validate
  script:
    - apt-get update && apt-get install -y jq bc
    - RULE_MODE=bypass DRY_RUN=true ./vercel-ip-allowlist.sh apply vendor-ips.csv

deploy:
  stage: deploy
  script:
    - apt-get update && apt-get install -y jq bc
    - RULE_MODE=bypass echo "yes" | ./vercel-ip-allowlist.sh apply vendor-ips.csv
  only:
    - main
  environment: production
```

## Migration from Bypass Rules

If you were using bypass rules and want to switch to allowlist:

1. **Export current bypass IPs** (if needed)
2. **Create allowlist CSV** with all IPs that should have access
3. **Test with dry run**: `DRY_RUN=true ./vercel-ip-allowlist.sh apply vendor-ips.csv`
4. **Apply allowlist**: `./vercel-ip-allowlist.sh apply vendor-ips.csv`
5. **Remove old bypass rules** (optional, they won't conflict)

> **Warning:** Allowlist rules are more restrictive than bypass rules. Make sure all necessary IPs are included before applying.

## API Reference

### Firewall Config API

| Operation | Endpoint | Method |
|-----------|----------|--------|
| Get config | `/v1/security/firewall/config/active?projectId=X` | GET |
| Update rules | `/v1/security/firewall/config?projectId=X` | PATCH |

### Rule Actions

| Action | Description |
|--------|-------------|
| `rules.insert` | Create new rule |
| `rules.update` | Update existing rule |
| `rules.remove` | Delete rule |

## Resources

- [Vercel Firewall Documentation](https://vercel.com/docs/security/firewall)
- [Vercel REST API - Security](https://vercel.com/docs/rest-api/reference/endpoints/security)
- [Vercel Rate Limits](https://vercel.com/docs/rest-api/limits)

## Plan Availability

- Firewall features require **Pro** or **Enterprise** plan
- Custom rules are part of the Firewall feature set
