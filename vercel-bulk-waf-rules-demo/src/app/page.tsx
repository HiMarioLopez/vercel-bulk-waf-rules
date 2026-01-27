"use client";

import * as motion from "motion/react-client";
import { useCallback, useEffect, useMemo, useState } from "react";

// Theme toggle hook
function useTheme() {
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const stored = document.documentElement.getAttribute("data-theme");
    if (stored === "dark" || stored === "light") {
      setTheme(stored);
    }
  }, []);

  const toggleTheme = useCallback(() => {
    const newTheme = theme === "light" ? "dark" : "light";
    setTheme(newTheme);
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
  }, [theme]);

  return { theme, toggleTheme, mounted };
}

function ThemeToggle() {
  const { theme, toggleTheme, mounted } = useTheme();

  if (!mounted) {
    return <div className="theme-toggle" aria-hidden="true" />;
  }

  return (
    <motion.button
      type="button"
      onClick={toggleTheme}
      className="theme-toggle"
      whileTap={{ scale: 0.95 }}
      aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
      title={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
    >
      {theme === "light" ? (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="square"
          aria-hidden="true"
        >
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      ) : (
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="square"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="5" />
          <line x1="12" y1="1" x2="12" y2="3" />
          <line x1="12" y1="21" x2="12" y2="23" />
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
          <line x1="1" y1="12" x2="3" y2="12" />
          <line x1="21" y1="12" x2="23" y2="12" />
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
        </svg>
      )}
    </motion.button>
  );
}

// Animation variants
const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
} as const;

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      type: "spring" as const,
      stiffness: 400,
      damping: 30,
    },
  },
};

// Default allowlist
const DEFAULT_ALLOWLIST = `# Private network ranges
127.0.0.1
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16`;

// Sample incoming requests for visualization
const INCOMING_REQUESTS = [
  { ip: "192.168.1.42", path: "/api/data" },
  { ip: "45.33.32.156", path: "/wp-admin" },
  { ip: "10.0.0.15", path: "/dashboard" },
  { ip: "203.0.113.50", path: "/login" },
  { ip: "172.16.0.8", path: "/api/users" },
  { ip: "198.51.100.23", path: "/.env" },
];

/**
 * Check if an IP is in a CIDR range
 */
function ipInCidr(ip: string, cidr: string): boolean {
  if (ip === "::1" && cidr === "::1") return true;

  const [range, bits] = cidr.split("/");
  if (!bits) return ip === cidr;

  const mask = Number.parseInt(bits, 10);
  if (Number.isNaN(mask)) return false;

  const ipParts = ip.split(".").map(Number);
  const rangeParts = range.split(".").map(Number);

  if (ipParts.length !== 4 || rangeParts.length !== 4) return false;
  if (
    ipParts.some((p) => Number.isNaN(p)) ||
    rangeParts.some((p) => Number.isNaN(p))
  )
    return false;

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
 * Parse allowlist text into array of IP/CIDR entries
 */
function parseAllowlist(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
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

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <motion.button
      type="button"
      onClick={handleCopy}
      className="btn px-4 py-2 text-sm"
      whileTap={{ scale: 0.95 }}
      aria-label={copied ? "Copied!" : "Copy to clipboard"}
    >
      {copied ? "COPIED!" : "COPY"}
    </motion.button>
  );
}

function StatusIndicator({ isAllowed }: { isAllowed: boolean }) {
  return (
    <motion.div
      className="flex items-center gap-3"
      key={isAllowed ? "allowed" : "blocked"}
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: "spring", stiffness: 500, damping: 25 }}
    >
      <div
        className={`h-3 w-3 rounded-full ${
          isAllowed
            ? "bg-[var(--accent-allowed)] pulse-allowed"
            : "bg-[var(--accent-blocked)] pulse-blocked"
        }`}
      />
      <span className="text-lg font-bold uppercase tracking-wider">
        {isAllowed ? "ALLOWED" : "BLOCKED"}
      </span>
    </motion.div>
  );
}

function RequestPacket({
  request,
  index,
  totalRequests,
}: {
  request: { ip: string; path: string; allowed: boolean };
  index: number;
  totalRequests: number;
}) {
  const delay = index * 1.2;

  return (
    <motion.div
      className="absolute left-3 flex items-center gap-2"
      initial={{ x: 0, opacity: 0 }}
      animate={{
        x: request.allowed ? [0, 120, 250] : [0, 120, 120],
        opacity: request.allowed ? [0, 1, 1, 0] : [0, 1, 1, 0],
      }}
      transition={{
        duration: request.allowed ? 2.5 : 1.8,
        delay,
        repeat: Number.POSITIVE_INFINITY,
        repeatDelay: totalRequests * 1.2 - 2.5 + 0.5,
        times: request.allowed ? [0, 0.4, 0.8, 1] : [0, 0.5, 0.8, 1],
        ease: "easeInOut",
      }}
      style={{ top: `${index * 40 + 4}px` }}
    >
      <div
        className={`border-2 border-[var(--border-color)] px-1.5 py-0.5 text-[10px] font-bold text-black ${
          request.allowed
            ? "bg-[var(--accent-allowed)]"
            : "bg-[var(--accent-blocked)]"
        }`}
      >
        <div className="tabular-nums">{request.ip}</div>
        <div className="text-[8px] opacity-70">{request.path}</div>
      </div>
    </motion.div>
  );
}

function FirewallVisualization({
  requests,
}: {
  requests: { ip: string; path: string; allowed: boolean }[];
}) {
  return (
    <motion.div
      className="card flex h-full flex-col justify-center p-6"
      variants={itemVariants}
    >
      <h2 className="mb-4 text-sm font-bold uppercase tracking-wider text-[var(--muted)]">
        FIREWALL IN ACTION
      </h2>

      <div className="relative">
        {/* Labels */}
        <div className="mb-2 grid grid-cols-3 text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
          <span className="text-left">INCOMING</span>
          <span className="text-center">FIREWALL</span>
          <span className="text-right">APP</span>
        </div>

        {/* Visualization container */}
        <div className="relative h-64 overflow-hidden border-[3px] border-[var(--border-color)] bg-[var(--card-bg-alt)]">
          {/* Request packets */}
          <div className="absolute inset-0 p-3">
            {requests.map((request, index) => (
              <RequestPacket
                key={`${request.ip}-${request.path}`}
                request={request}
                index={index}
                totalRequests={requests.length}
              />
            ))}
          </div>

          {/* Firewall barrier */}
          <motion.div
            className="absolute left-1/2 top-0 h-full w-0.5 -translate-x-1/2 bg-[var(--border-color)]"
            initial={{ scaleY: 0 }}
            animate={{ scaleY: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          />

          {/* Firewall box */}
          <motion.div
            className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 border-2 border-[var(--border-color)] bg-[var(--card-bg)] px-2 py-1.5"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{
              type: "spring",
              stiffness: 400,
              damping: 25,
              delay: 0.5,
            }}
          >
            <div className="text-center text-[10px] font-bold uppercase tracking-wider">
              IP
              <br />
              CHECK
            </div>
          </motion.div>

          {/* App box on the right */}
          <motion.div
            className="absolute right-1 top-1/2 -translate-y-1/2 border-2 border-[var(--border-color)] bg-[var(--accent-allowed)] px-1.5 py-3"
            initial={{ x: 20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ delay: 0.7 }}
          >
            <div className="text-[8px] font-bold uppercase tracking-wider text-black [writing-mode:vertical-rl]">
              APP
            </div>
          </motion.div>
        </div>

        {/* Legend */}
        <div className="mt-3 flex justify-center gap-4 text-[10px] font-medium">
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 border-2 border-[var(--border-color)] bg-[var(--accent-allowed)]" />
            <span>Allowed</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 border-2 border-[var(--border-color)] bg-[var(--accent-blocked)]" />
            <span>Blocked</span>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function AllowlistEditor({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="mt-4">
      <label
        htmlFor="allowlist"
        className="mb-2 block text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]"
      >
        EDIT ALLOWLIST (one per line, # for comments)
      </label>
      <textarea
        id="allowlist"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-28 w-full resize-none border-2 border-[var(--border-color)] bg-[var(--card-bg-alt)] p-2 font-mono text-xs text-[var(--foreground)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-allowed)]"
        spellCheck={false}
        placeholder="Enter IPs or CIDR ranges..."
      />
    </div>
  );
}

export default function Home() {
  const [userIp, setUserIp] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [allowlistText, setAllowlistText] = useState(DEFAULT_ALLOWLIST);

  // Parse allowlist from text
  const allowlist = useMemo(
    () => parseAllowlist(allowlistText),
    [allowlistText],
  );

  // Check if user's IP is allowed
  const isUserAllowed = useMemo(() => {
    if (!userIp) return false;
    return checkIpInAllowlist(userIp, allowlist);
  }, [userIp, allowlist]);

  // Generate request statuses based on current allowlist
  const requests = useMemo(() => {
    return INCOMING_REQUESTS.map((req) => ({
      ...req,
      allowed: checkIpInAllowlist(req.ip, allowlist),
    }));
  }, [allowlist]);

  // Count allowed/blocked
  const stats = useMemo(() => {
    const allowed = requests.filter((r) => r.allowed).length;
    return { allowed, blocked: requests.length - allowed };
  }, [requests]);

  const handleAllowlistChange = useCallback((value: string) => {
    setAllowlistText(value);
  }, []);

  useEffect(() => {
    const fetchIp = async () => {
      try {
        const res = await fetch("/api/ip");
        const data = await res.json();
        setUserIp(data.ip);
      } catch {
        setUserIp("Unable to detect");
      } finally {
        setLoading(false);
      }
    };

    fetchIp();
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-[var(--background)]">
      {/* Header */}
      <header className="border-b-[3px] border-[var(--border-color)] bg-[var(--card-bg)]">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <h1 className="text-lg font-bold uppercase tracking-wider">
            VERCEL BULK WAF RULES
          </h1>
          <div className="flex items-center gap-3">
            <a
              href="https://vercel.com/docs/vercel-firewall"
              target="_blank"
              rel="noopener noreferrer"
              className="btn px-4 py-2 text-sm"
              aria-label="View Vercel Firewall docs"
            >
              DOCS ↗
            </a>
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col justify-center px-6 py-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="show"
          className="grid gap-6 lg:grid-cols-2"
        >
          {/* Left Column - IP Info & Allowlist Editor */}
          <div className="flex flex-col gap-6">
            {/* IP Display Card */}
            <motion.section className="card p-6" variants={itemVariants}>
              <h2 className="mb-4 text-sm font-bold uppercase tracking-wider text-[var(--muted)]">
                YOUR IP ADDRESS
              </h2>
              <div className="flex flex-wrap items-center justify-between gap-4">
                {loading ? (
                  <motion.div
                    className="h-10 w-48 bg-[var(--card-bg-alt)]"
                    animate={{ opacity: [0.5, 1, 0.5] }}
                    transition={{
                      repeat: Number.POSITIVE_INFINITY,
                      duration: 1.5,
                    }}
                  />
                ) : (
                  <motion.span
                    className="tabular-nums text-2xl font-bold tracking-tight md:text-3xl"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ type: "spring", stiffness: 400, damping: 30 }}
                  >
                    {userIp}
                  </motion.span>
                )}
                {userIp && <CopyButton text={userIp} />}
              </div>

              {/* Status inline */}
              <div className="mt-4 flex items-center justify-between border-t-2 border-dashed border-[var(--muted-border)] pt-4">
                <span className="text-xs font-medium uppercase text-[var(--muted)]">
                  Status
                </span>
                {!loading && <StatusIndicator isAllowed={isUserAllowed} />}
              </div>
            </motion.section>

            {/* Allowlist Editor Card */}
            <motion.section className="card flex-1 p-6" variants={itemVariants}>
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--muted)]">
                  IP ALLOWLIST
                </h2>
                <div className="flex gap-3 text-[10px] font-bold">
                  <span className="text-[var(--stats-pass)]">
                    {stats.allowed} PASS
                  </span>
                  <span className="text-[var(--stats-block)]">
                    {stats.blocked} BLOCK
                  </span>
                </div>
              </div>

              <AllowlistEditor
                value={allowlistText}
                onChange={handleAllowlistChange}
              />

              <p className="mt-3 text-[10px] text-[var(--muted)]">
                Edit the allowlist above and watch the firewall animation update
                in real-time. Add your IP to allow yourself!
              </p>
            </motion.section>
          </div>

          {/* Right Column - Firewall Visualization */}
          <FirewallVisualization requests={requests} />
        </motion.div>
      </main>

      {/* Footer */}
      <footer className="border-t-[3px] border-[var(--border-color)] bg-[var(--card-bg)]">
        <div className="mx-auto max-w-5xl px-6 py-6 text-center text-sm text-[var(--muted)]">
          <p>
            Built with{" "}
            <a
              href="https://nextjs.org"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-[var(--foreground)] underline"
            >
              Next.js
            </a>{" "}
            and deployed on{" "}
            <a
              href="https://vercel.com"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-[var(--foreground)] underline"
            >
              Vercel
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
