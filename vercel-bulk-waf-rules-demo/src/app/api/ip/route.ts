import { type NextRequest, NextResponse } from "next/server";

// Demo allowlist - in production this would come from env/config
const DEMO_ALLOWLIST = [
  "127.0.0.1",
  "::1",
  // Add some example ranges
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
];

/**
 * Check if an IP is in a CIDR range
 */
function ipInCidr(ip: string, cidr: string): boolean {
  // Handle IPv6 localhost
  if (ip === "::1" && cidr === "::1") return true;

  const [range, bits] = cidr.split("/");
  if (!bits) return ip === cidr;

  const mask = Number.parseInt(bits, 10);
  if (Number.isNaN(mask)) return false;

  // Convert IP to number (IPv4 only for demo)
  const ipParts = ip.split(".").map(Number);
  const rangeParts = range.split(".").map(Number);

  if (ipParts.length !== 4 || rangeParts.length !== 4) return false;

  const ipNum =
    (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const rangeNum =
    (rangeParts[0] << 24) |
    (rangeParts[1] << 16) |
    (rangeParts[2] << 8) |
    rangeParts[3];
  const maskNum = ~((1 << (32 - mask)) - 1);

  return (ipNum & maskNum) === (rangeNum & maskNum);
}

/**
 * Check if IP is in allowlist
 */
function checkIpInAllowlist(ip: string, allowlist: string[]): boolean {
  for (const entry of allowlist) {
    if (entry.includes("/")) {
      if (ipInCidr(ip, entry)) return true;
    } else if (ip === entry) {
      return true;
    }
  }
  return false;
}

export async function GET(request: NextRequest) {
  // Get IP from various headers
  const forwarded = request.headers.get("x-forwarded-for");
  const realIp = request.headers.get("x-real-ip");
  const vercelIp = request.headers.get("x-vercel-forwarded-for");

  // Use first IP from forwarded header, or fall back to others
  const ip =
    forwarded?.split(",")[0]?.trim() ||
    vercelIp?.split(",")[0]?.trim() ||
    realIp ||
    "Unknown";

  const isAllowed = ip !== "Unknown" && checkIpInAllowlist(ip, DEMO_ALLOWLIST);

  return NextResponse.json({
    ip,
    isAllowed,
    checkedAt: new Date().toISOString(),
  });
}
