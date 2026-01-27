# Vercel IP Allowlist - Firewall Rules for Whitelisted IPs

Automation scripts to create IP allowlist rules in Vercel Firewall with **two modes**:

| Mode | Description | Use Case |
|------|-------------|----------|
| **deny** (default) | Block all traffic EXCEPT from whitelisted IPs | Private apps, vendor-only access |
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

**Deny Mode (default)** - Block all except allowlisted IPs:

```bash
./vercel-ip-allowlist.sh apply vendor-ips.csv
```

After applying, **only IPs in your whitelist can access your project**. All other traffic is blocked.

**Bypass Mode** - Bypass WAF for allowlisted IPs (public apps):

```bash
RULE_MODE=bypass ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

After applying, **listed IPs bypass WAF/security checks**. All other traffic flows normally through security rules. Use this for vendor integrations like webhooks, security scanners, or SEO bots.

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
| `cloudflare-export.sh` | Export IPs from Cloudflare (useful for migration) |
| `vendor-ips.csv` | Template CSV file |

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

Create a Vercel API token at <https://vercel.com/account/tokens> with these scopes:

| Scope | Required | Purpose |
|-------|----------|---------|
| `read:project` | Yes | Fetch current firewall config |
| `write:project` | Yes | Create/update/delete rules |
| `read:team` | For teams | Access team projects |
| `write:team` | For teams | Modify team project rules |

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
