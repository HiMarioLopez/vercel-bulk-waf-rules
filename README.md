# Vercel Bulk WAF Rules

Bulk manage Vercel WAF (Web Application Firewall) rules via CSV. Supports IP allowlisting and WAF bypass.

## What's Inside

```plaintext
vercel-bulk-waf-rules/
├── vercel-bulk-waf-rules-scripts/   # Bash scripts for managing WAF rules
└── vercel-bulk-waf-rules-demo/      # Next.js demo app for testing
```

## Quick Start

### 1. Setup

```bash
cd vercel-bulk-waf-rules-scripts
vercel link    # Link to your project (one-time)
vercel login   # Authenticate (one-time)
```

### 2. Create IP CSV

```csv
ip,vendor_name,notes
1.2.3.4,Acme Corp,Payment gateway
5.6.7.0/24,Partner Inc,API integration
```

### 3. Preview Changes

```bash
DRY_RUN=true RULE_MODE=deny ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### 4. Apply

```bash
RULE_MODE=deny ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

## Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **deny** | Block all traffic EXCEPT listed IPs | Private apps, vendor-only access |
| **bypass** | Bypass WAF for listed IPs | Public apps with vendor integrations |

## Commands

```bash
./vercel-bulk-waf-rules.sh apply <csv>    # Create/update WAF rules
./vercel-bulk-waf-rules.sh show           # Show current rules
./vercel-bulk-waf-rules.sh optimize <csv> # Optimize IPs into CIDRs
./vercel-bulk-waf-rules.sh disable        # Temporarily disable
./vercel-bulk-waf-rules.sh remove         # Remove a single rule
./vercel-bulk-waf-rules.sh purge          # Remove ALL auto-managed rules
./vercel-bulk-waf-rules.sh backup         # Export firewall config
```

## Requirements

- Vercel account (WAF Custom Rules available on [all plans](https://vercel.com/docs/plans))
- `vercel` CLI v50.5.1+ (or `npx vercel@latest`)
- `jq` and `bc` installed

## Documentation

See [`vercel-bulk-waf-rules-scripts/README.md`](./vercel-bulk-waf-rules-scripts/README.md) for complete documentation.

## License

MIT
