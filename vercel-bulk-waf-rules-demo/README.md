# Vercel Bulk WAF Rules Demo

A Next.js demo app for testing Vercel WAF rules. Includes an IP detection endpoint to verify your firewall configuration.

## Features

- `/api/ip` - Returns the client's IP address (useful for testing allowlist rules)
- Clean UI for visualizing IP information

## Getting Started

```bash
bun install
bun dev
```

Open [http://localhost:3000](http://localhost:3000) to see the app.

## Deploy

Deploy to Vercel, then use the `vercel-bulk-waf-rules.sh` script to apply WAF rules to the project.

## Tech Stack

- Next.js 16
- React 19
- Tailwind CSS 4
- Biome (linting/formatting)
