# Vercel IP Allowlist

Automation tools to manage IP allowlist rules in Vercel Firewall. Block all traffic except from whitelisted IPs.

## What's Inside

```plaintext
vercel-ip-allowlist/
├── vercel-ip-allowlist-scripts/   # Bash scripts for managing firewall rules
└── vercel-ip-allowlist-demo/      # Next.js demo app for visualizing allowlists
```

## Quick Start

### 1. Set Environment Variables

```bash
export VERCEL_TOKEN="your-vercel-api-token"
export PROJECT_ID="prj_xxxxxxxxxxxx"
export TEAM_ID="team_xxxxxxxxxxxx"  # Optional, for team projects
```

### 2. Create IP Allowlist CSV

```csv
ip,vendor_name,notes
1.2.3.4,Acme Corp,Payment gateway
5.6.7.0/24,Partner Inc,API integration
```

### 3. Preview Changes

```bash
cd vercel-ip-allowlist-scripts
DRY_RUN=true ./vercel-ip-allowlist.sh apply vendor-ips.csv
```

### 4. Apply

```bash
./vercel-ip-allowlist.sh apply vendor-ips.csv
```

## How It Works

```plaintext
┌─────────────────────────────────────────────────────────────────┐
│  ALLOWLIST RULES                                                │
│  ──────────────────────────                                     │
│  Whitelisted IPs → Your App                                     │
│  All Other IPs   → BLOCKED                                      │
│                                                                 │
│  Result: ONLY whitelisted traffic reaches your app              │
└─────────────────────────────────────────────────────────────────┘
```

This creates a single Vercel Firewall rule using the `ninc` (NOT IN) operator to deny traffic from IPs not in your allowlist.

## Scripts

| Script | Purpose |
|--------|---------|
| `vercel-ip-allowlist.sh` | Main script - create, update, show, disable, remove allowlist rules |
| `rollback.sh` | Backup, restore, and manage rule state |
| `cloudflare-export.sh` | Export IPs from Cloudflare Access policies |

## Commands

```bash
./vercel-ip-allowlist.sh apply <csv>   # Create/update allowlist
./vercel-ip-allowlist.sh show          # Show current config
./vercel-ip-allowlist.sh disable       # Temporarily disable (keeps config)
./vercel-ip-allowlist.sh remove        # Remove rule entirely
./vercel-ip-allowlist.sh backup        # Export firewall config
```

## Requirements

- Vercel Pro or Enterprise plan (Firewall feature)
- Bash with `jq` and `bc` installed
- Vercel API token with `read:project` and `write:project` scopes

## Documentation

See [`vercel-ip-allowlist-scripts/README.md`](./vercel-ip-allowlist-scripts/README.md) for complete documentation including:

- Environment variables reference
- CSV format specification
- Hostname scoping
- Rollback operations
- CI/CD integration (GitHub Actions, GitLab CI)
- Troubleshooting guide

## License

MIT
