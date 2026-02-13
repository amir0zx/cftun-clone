import { motion } from "framer-motion";
import {
  Activity,
  Cloud,
  Database,
  Download,
  Gauge,
  Play,
  Radar,
  RefreshCw,
  Search,
  Shield,
  Square,
  Wifi,
} from "lucide-react";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Toaster, toast } from "sonner";
import * as XLSX from "xlsx";

type ProbeState = "success" | "failed" | "timeout" | "pending";
type BatchStatus = "running" | "completed" | "cancelled";
type Tab =
  | "scanner"
  | "sources"
  | "history"
  | "results"
  | "analytics"
  | "export"
  | "dns"
  | "vless";

type ExportFormat = "txt" | "json" | "xlsx";

type ExportRow = Record<string, string | number | null>;

type ProbeResponse = {
  ip: string;
  mode: "l4_tcp_handshake";
  testedPorts: number[];
  overall: "success" | "failed";
  l4: Array<{ port: number; status: ProbeState; latency: number | null }>;
};

type ScanResult = {
  id: string;
  batchId: string;
  ipAddress: string;
  ipRange: string;
  overall: ProbeState;
  // Full L4 results for all tested ports (required for capability tags + exports).
  // Older stored results may not have this field; we migrate them on load.
  l4?: ProbeResponse["l4"];
  tcp80: ProbeState;
  tcp443: ProbeState;
  tcp2053: ProbeState;
  tcp8443: ProbeState;
  openPorts: number;
  latency: number | null;
  createdAt: string;
};

type CapabilityId = "cdn" | "tunnel" | "warp" | "bpb";

type CapabilityFlags = Record<CapabilityId, boolean>;

type ProxyExportProtocol = "vless_ws_tls" | "trojan_ws_tls";

type ProxyExportSettings = {
  protocol: ProxyExportProtocol;
  secret: string; // UUID (vless) or password (trojan)
  sni: string;
  host: string;
  path: string;
  preferredPortsCsv: string; // e.g. "443,2053,8443"
  includeCaps: CapabilityId[]; // filter nodes by capabilities; empty = no filter
};

type DnsReplaceMode = "replace";

type DnsSettings = {
  token: string;
  zoneId: string;
  recordName: string;
  topN: number;
  proxied: boolean;
  ttl: number; // 1 = auto
  includeCaps: CapabilityId[];
  mode: DnsReplaceMode;
};

type SourceGroupId = "cdn" | "warp" | "tunnel" | "custom";

type VlessRetestResult = {
  ip: string;
  port: number;
  status: ProbeState;
  latency: number | null;
};

type VlessSettings = {
  vlessUri: string;
  uuid: string;
  port: number;
  sni: string;
  host: string;
  path: string;
  topN: number;
  concurrency: number;
};

type ScanBatch = {
  id: string;
  name: string;
  createdAt: string;
  durationMs?: number;
  status: BatchStatus;
  totalIps: number;
  scannedCount: number;
  successCount: number;
  failedCount: number;
  ipRanges: string[];
};

type SourceItem = {
  id: string;
  name: string;
  url: string;
  ranges: string[];
  lastFetched: string | null;
  group?: "cdn" | "warp" | "tunnel" | "custom";
};

type LogEntry = {
  id: string;
  ts: string;
  level: "info" | "ok" | "warn" | "error";
  text: string;
};

const STORAGE_KEYS = {
  history: "cftun_history_v2",
  results: "cftun_results_v2",
  ranges: "cftun_ranges_v2",
  sources: "cftun_sources_v2",
  proxyExport: "cftun_proxy_export_v1",
  dns: "cftun_dns_v1",
  vless: "cftun_vless_v1",
  apiBaseUrl: "cftun_api_base_url_v1",
};

const DEFAULT_RANGES = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
];

function readStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage<T>(key: string, value: T): void {
  localStorage.setItem(key, JSON.stringify(value));
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportRows(
  format: ExportFormat,
  rows: ExportRow[],
  filenameBase: string,
): void {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const name = `${filenameBase}_${ts}`;

  if (format === "json") {
    downloadBlob(
      new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }),
      `${name}.json`,
    );
    return;
  }

  if (format === "txt") {
    const text = rows.map((r) => Object.values(r)[0]).join("\n");
    downloadBlob(new Blob([text], { type: "text/plain" }), `${name}.txt`);
    return;
  }

  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "export");
  const out = XLSX.write(wb, { bookType: "xlsx", type: "array" });
  downloadBlob(
    new Blob([out], {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }),
    `${name}.xlsx`,
  );
}

function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".");
  return (
    parts.length === 4 &&
    parts.every(
      (part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255,
    )
  );
}

function isValidCidr(v: string): boolean {
  const [ip, prefixRaw] = v.trim().split("/");
  if (!ip || !prefixRaw) return false;
  const prefix = Number(prefixRaw);
  return (
    isValidIPv4(ip) && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32
  );
}

function ipToInt(ip: string): number {
  const [a, b, c, d] = ip.split(".").map(Number);
  return (((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0;
}

function intToIp(v: number): string {
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(
    ".",
  );
}

function expandCidr(cidr: string, limit: number): string[] {
  if (!isValidCidr(cidr)) return [];
  const [ip, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const hostCount = 2 ** (32 - prefix);
  const count = Math.min(hostCount, Math.max(1, limit));
  const base = ipToInt(ip);
  const out: string[] = [];
  for (let i = 1; i <= count; i += 1) out.push(intToIp((base + i) >>> 0));
  return out;
}

function sampleCidr(
  cidr: string,
  limit: number,
  mode: "sequential" | "random",
): string[] {
  if (mode === "sequential") return expandCidr(cidr, limit);
  if (!isValidCidr(cidr)) return [];

  const [ip, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const hostCount = 2 ** (32 - prefix);
  const count = Math.min(hostCount, Math.max(1, limit));
  const base = ipToInt(ip);

  // CFScanner-inspired behavior: sample random IPs in each subnet rather than taking first N.
  const picked = new Set<number>();
  const maxIndex = Math.max(1, hostCount - 2);
  const maxAttempts = Math.min(10_000, count * 50);

  let attempts = 0;
  while (picked.size < count && attempts < maxAttempts) {
    attempts += 1;
    const idx = 1 + Math.floor(Math.random() * maxIndex);
    picked.add(idx);
  }

  return [...picked].map((idx) => intToIp((base + idx) >>> 0));
}

function extractCidrs(payload: unknown): string[] {
  const found = new Set<string>();
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      const matches =
        value.match(
          /\b(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])\b/g,
        ) || [];
      matches.forEach((m) => {
        if (isValidCidr(m)) found.add(m);
      });
      return;
    }
    if (Array.isArray(value)) return value.forEach(walk);
    if (value && typeof value === "object")
      Object.values(value as Record<string, unknown>).forEach(walk);
  };
  walk(payload);
  return [...found];
}

function Progress({ value }: { value: number }) {
  return (
    <div className="progress-shell">
      <motion.div
        className="progress-bar"
        animate={{ width: `${value}%` }}
        transition={{ duration: 0.35 }}
      />
    </div>
  );
}

function migrateStoredScanResult(raw: unknown): ScanResult | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Partial<ScanResult> & Record<string, unknown>;
  if (
    typeof r.id !== "string" ||
    typeof r.batchId !== "string" ||
    typeof r.ipAddress !== "string" ||
    typeof r.ipRange !== "string" ||
    typeof r.overall !== "string" ||
    typeof r.createdAt !== "string"
  )
    return null;

  const base: ScanResult = {
    id: r.id,
    batchId: r.batchId,
    ipAddress: r.ipAddress,
    ipRange: r.ipRange,
    overall: r.overall as ProbeState,
    tcp80: (r.tcp80 as ProbeState) ?? "failed",
    tcp443: (r.tcp443 as ProbeState) ?? "failed",
    tcp2053: (r.tcp2053 as ProbeState) ?? "failed",
    tcp8443: (r.tcp8443 as ProbeState) ?? "failed",
    openPorts: typeof r.openPorts === "number" ? r.openPorts : 0,
    latency:
      typeof r.latency === "number" || r.latency === null ? r.latency : null,
    createdAt: r.createdAt,
    l4: Array.isArray(r.l4)
      ? (r.l4 as ProbeResponse["l4"])
      : [
          { port: 80, status: (r.tcp80 as ProbeState) ?? "failed", latency: null },
          {
            port: 443,
            status: (r.tcp443 as ProbeState) ?? "failed",
            latency: null,
          },
          {
            port: 2053,
            status: (r.tcp2053 as ProbeState) ?? "failed",
            latency: null,
          },
          {
            port: 8443,
            status: (r.tcp8443 as ProbeState) ?? "failed",
            latency: null,
          },
        ],
  };
  return base;
}

function l4Status(result: ScanResult, port: number): ProbeState {
  const hit = result.l4?.find((p) => p.port === port);
  if (hit) return hit.status;
  // Fallback for legacy fields
  if (port === 80) return result.tcp80;
  if (port === 443) return result.tcp443;
  if (port === 2053) return result.tcp2053;
  if (port === 8443) return result.tcp8443;
  return "failed";
}

function capabilityFlags(result: ScanResult): CapabilityFlags {
  const cdn = l4Status(result, 80) === "success" || l4Status(result, 443) === "success";
  const tunnel = l4Status(result, 7844) === "success";
  // WARP is primarily UDP; this is a TCP-only heuristic for users who test TCP:2408.
  const warp = l4Status(result, 2408) === "success";
  const bpb = l4Status(result, 8080) === "success";
  return { cdn, tunnel, warp, bpb };
}

function parsePreferredPorts(csv: string): number[] {
  return csv
    .split(",")
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
}

function pickOpenPort(result: ScanResult, preferred: number[]): number | null {
  const open = new Set<number>(
    (result.l4 || []).filter((p) => p.status === "success").map((p) => p.port),
  );
  for (const p of preferred) if (open.has(p)) return p;
  const any = (result.l4 || []).find((p) => p.status === "success")?.port;
  if (typeof any === "number") return any;
  return preferred[0] ?? null;
}

function yamlEscape(s: string): string {
  // Minimal YAML escaping sufficient for our generated Clash config.
  if (/^[a-zA-Z0-9_.:/-]+$/.test(s)) return s;
  return JSON.stringify(s);
}

async function probeIp(
  apiBaseUrl: string,
  ip: string,
  ports: number[],
  signal?: AbortSignal,
): Promise<ProbeResponse> {
  const base = apiBaseUrl.trim().replace(/\/+$/g, "");
  const url = base ? `${base}/api/probe` : "/api/probe";
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ip, ports }),
    signal,
  });
  if (!response.ok) throw new Error("Probe API error");
  return (await response.json()) as ProbeResponse;
}

async function cfReplaceARecords(input: {
  apiBaseUrl?: string;
  token: string;
  zoneId: string;
  name: string;
  ips: string[];
  proxied: boolean;
  ttl: number;
}): Promise<{ ok: boolean; replaced?: unknown; error?: string }> {
  const base = String(input.apiBaseUrl || "").trim().replace(/\/+$/g, "");
  const url = base ? `${base}/api/cf/dns/replace-a` : "/api/cf/dns/replace-a";
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...input, apiBaseUrl: undefined }),
  });
  const json = (await res.json().catch(() => null)) as
    | { ok: boolean; replaced?: unknown; error?: string }
    | null;
  if (!res.ok || !json) throw new Error(json?.error || "Cloudflare API failed");
  return json;
}

function parseVlessUri(uri: string): VlessSettings | null {
  try {
    const u = new URL(uri.trim());
    if (u.protocol !== "vless:") return null;
    const uuid = decodeURIComponent(u.username || "");
    const port = Number(u.port || 443);
    const q = u.searchParams;
    const sni = q.get("sni") || q.get("servername") || "";
    const host = q.get("host") || "";
    const path = q.get("path") || "/";
    return {
      vlessUri: uri.trim(),
      uuid,
      port: Number.isFinite(port) ? port : 443,
      sni,
      host,
      path,
      topN: 20,
      concurrency: 20,
    };
  } catch {
    return null;
  }
}

function buildVlessUri(input: {
  ip: string;
  port: number;
  uuid: string;
  sni: string;
  host: string;
  path: string;
  name?: string;
}): string {
  const base = new URL(`vless://${encodeURIComponent(input.uuid)}@${input.ip}:${input.port}`);
  base.searchParams.set("type", "ws");
  base.searchParams.set("security", "tls");
  if (input.sni) base.searchParams.set("sni", input.sni);
  if (input.host) base.searchParams.set("host", input.host);
  if (input.path) base.searchParams.set("path", input.path);
  // Common defaults
  base.searchParams.set("encryption", "none");
  const fragment = input.name ? `#${encodeURIComponent(input.name)}` : "";
  return `${base.toString()}${fragment}`;
}

function App() {
  const [ranges, setRanges] = useState<string[]>(() =>
    readStorage(STORAGE_KEYS.ranges, DEFAULT_RANGES),
  );
  const [apiBaseUrl, setApiBaseUrl] = useState<string>(() =>
    readStorage<string>(STORAGE_KEYS.apiBaseUrl, ""),
  );
  const [selectedRanges, setSelectedRanges] = useState<string[]>([]);
  const [history, setHistory] = useState<ScanBatch[]>(() =>
    readStorage(STORAGE_KEYS.history, []),
  );
  const [allResults, setAllResults] = useState<ScanResult[]>(() =>
    readStorage<unknown[]>(STORAGE_KEYS.results, [])
      .map(migrateStoredScanResult)
      .filter((v): v is ScanResult => v != null),
  );
  const [sources, setSources] = useState<SourceItem[]>(() =>
    readStorage(STORAGE_KEYS.sources, []),
  );

  const [activeTab, setActiveTab] = useState<Tab>("scanner");
  const [isScanning, setIsScanning] = useState(false);
  const [currentBatch, setCurrentBatch] = useState<ScanBatch | null>(null);
  const [liveResults, setLiveResults] = useState<ScanResult[]>([]);
  const [ipsPerRange, setIpsPerRange] = useState(3);
  const [rangeGroup, setRangeGroup] = useState<
    "all" | "cdn" | "tunnel" | "warp" | "custom"
  >("all");
  const [rangePage, setRangePage] = useState(1);
  const [rangePageSize, setRangePageSize] = useState(90);

  const [historyQuery, setHistoryQuery] = useState("");
  const [historyDate, setHistoryDate] = useState("");

  const [sourceName, setSourceName] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [sourceGroup, setSourceGroup] = useState<SourceGroupId>("custom");
  const [portToggles, setPortToggles] = useState<number[]>([
    80, 443, 7844, 2053, 2083, 2087, 2096, 8443, 8080, 2408,
  ]);
  const [customPort, setCustomPort] = useState("");
  const [scanWorkers, setScanWorkers] = useState(20);
  const [sampleMode, setSampleMode] = useState<"sequential" | "random">(
    "random",
  );

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [resultFilterQuery, setResultFilterQuery] = useState("");
  const [resultFilterStatus, setResultFilterStatus] = useState<
    "all" | "success" | "failed"
  >("all");
  const [resultFilterMinOpen, setResultFilterMinOpen] = useState(0);
  const [resultOnlyLastBatch, setResultOnlyLastBatch] = useState(true);
  const [resultFilterCaps, setResultFilterCaps] = useState<CapabilityId[]>([]);

  const [proxyExport, setProxyExport] = useState<ProxyExportSettings>(() =>
    readStorage<ProxyExportSettings>(STORAGE_KEYS.proxyExport, {
      protocol: "vless_ws_tls",
      secret: "",
      sni: "",
      host: "",
      path: "/",
      preferredPortsCsv: "443,2053,8443,80",
      includeCaps: ["cdn"],
    }),
  );

  const [dnsSettings, setDnsSettings] = useState<DnsSettings>(() =>
    readStorage<DnsSettings>(STORAGE_KEYS.dns, {
      token: "",
      zoneId: "",
      recordName: "",
      topN: 5,
      proxied: true,
      ttl: 1,
      includeCaps: ["cdn"],
      mode: "replace",
    }),
  );

  const [vlessSettings, setVlessSettings] = useState<VlessSettings>(() =>
    readStorage<VlessSettings>(STORAGE_KEYS.vless, {
      vlessUri: "",
      uuid: "",
      port: 443,
      sni: "",
      host: "",
      path: "/",
      topN: 20,
      concurrency: 20,
    }),
  );
  const [vlessResults, setVlessResults] = useState<VlessRetestResult[]>([]);
  const [vlessIsTesting, setVlessIsTesting] = useState(false);

  const runRef = useRef(false);
  const abortersRef = useRef<AbortController[]>([]);

  function pushLog(level: LogEntry["level"], text: string): void {
    const entry: LogEntry = {
      id: crypto.randomUUID(),
      ts: new Date().toLocaleTimeString(),
      level,
      text,
    };
    setLogs((prev) => [entry, ...prev].slice(0, 250));
  }

  function togglePort(port: number): void {
    setPortToggles((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port],
    );
  }

  function addCustomPort(): void {
    const p = Number(customPort.trim());
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      toast.error("Invalid port");
      return;
    }
    setPortToggles((prev) => (prev.includes(p) ? prev : [...prev, p]));
    setCustomPort("");
  }

  useEffect(() => writeStorage(STORAGE_KEYS.ranges, ranges), [ranges]);
  useEffect(() => writeStorage(STORAGE_KEYS.history, history), [history]);
  useEffect(() => writeStorage(STORAGE_KEYS.results, allResults), [allResults]);
  useEffect(() => writeStorage(STORAGE_KEYS.sources, sources), [sources]);
  useEffect(() => writeStorage(STORAGE_KEYS.proxyExport, proxyExport), [proxyExport]);
  useEffect(() => writeStorage(STORAGE_KEYS.dns, dnsSettings), [dnsSettings]);
  useEffect(() => writeStorage(STORAGE_KEYS.vless, vlessSettings), [vlessSettings]);
  useEffect(() => writeStorage(STORAGE_KEYS.apiBaseUrl, apiBaseUrl), [apiBaseUrl]);

  const mergedResults = liveResults.length ? liveResults : allResults;

  const rangesBySourceGroup = useMemo(() => {
    const m = new Map<SourceGroupId, Set<string>>();
    const add = (g: SourceGroupId, cidr: string) => {
      if (!m.has(g)) m.set(g, new Set<string>());
      m.get(g)!.add(cidr);
    };
    for (const s of sources) {
      const g = (s.group || "custom") as SourceGroupId;
      for (const r of s.ranges || []) add(g, r);
    }
    return m;
  }, [sources]);

  const filteredRanges = useMemo(() => {
    const all = [...new Set(ranges)];
    const defaults = new Set(DEFAULT_RANGES);
    const inGroup = (cidr: string, g: typeof rangeGroup): boolean => {
      if (g === "all") return true;
      if (g === "cdn") {
        return (
          defaults.has(cidr) ||
          (rangesBySourceGroup.get("cdn")?.has(cidr) ?? false)
        );
      }
      if (g === "tunnel") return rangesBySourceGroup.get("tunnel")?.has(cidr) ?? false;
      if (g === "warp") return rangesBySourceGroup.get("warp")?.has(cidr) ?? false;
      // custom
      if (defaults.has(cidr)) return false;
      return true;
    };
    return all.filter((c) => inGroup(c, rangeGroup));
  }, [rangeGroup, ranges, rangesBySourceGroup]);

  const rangeTotalPages = useMemo(() => {
    const size = Math.max(10, Math.min(300, rangePageSize || 90));
    return Math.max(1, Math.ceil(filteredRanges.length / size));
  }, [filteredRanges.length, rangePageSize]);

  const pagedRanges = useMemo(() => {
    const size = Math.max(10, Math.min(300, rangePageSize || 90));
    const page = Math.max(1, Math.min(rangeTotalPages, rangePage));
    const start = (page - 1) * size;
    return filteredRanges.slice(start, start + size);
  }, [filteredRanges, rangePage, rangePageSize, rangeTotalPages]);

  const stats = useMemo(() => {
    const success = mergedResults.filter((r) => r.overall === "success").length;
    const failed = mergedResults.filter((r) => r.overall === "failed").length;
    const timeout = mergedResults.filter(
      (r) =>
        r.l4?.some((p) => p.status === "timeout") ||
        r.tcp80 === "timeout" ||
        r.tcp443 === "timeout" ||
        r.tcp2053 === "timeout" ||
        r.tcp8443 === "timeout",
    ).length;
    return { success, failed, timeout };
  }, [mergedResults]);

  const historyFiltered = useMemo(() => {
    const q = historyQuery.trim().toLowerCase();
    return history.filter((b) => {
      const queryOk =
        !q ||
        b.name.toLowerCase().includes(q) ||
        b.ipRanges.some((r) => r.toLowerCase().includes(q));
      const dateOk = !historyDate || b.createdAt.slice(0, 10) === historyDate;
      return queryOk && dateOk;
    });
  }, [history, historyDate, historyQuery]);

  const pieData = [
    { name: "Success", value: stats.success },
    { name: "Failed", value: stats.failed },
    { name: "Timeout", value: stats.timeout },
  ];

  const chartData = useMemo(() => {
    const byMinute = new Map<string, number>();
    mergedResults.forEach((r) => {
      const k = r.createdAt.slice(0, 16).replace("T", " ");
      byMinute.set(k, (byMinute.get(k) || 0) + 1);
    });
    return [...byMinute.entries()]
      .slice(-22)
      .map(([time, count]) => ({ time, count }));
  }, [mergedResults]);

  const filteredResults = useMemo(() => {
    const q = resultFilterQuery.trim().toLowerCase();
    let base = mergedResults;
    if (resultOnlyLastBatch && currentBatch)
      base = base.filter((r) => r.batchId === currentBatch.id);
    if (q)
      base = base.filter(
        (r) => r.ipAddress.includes(q) || r.ipRange.toLowerCase().includes(q),
      );
    if (resultFilterStatus !== "all")
      base = base.filter((r) => r.overall === resultFilterStatus);
    base = base.filter((r) => r.openPorts >= resultFilterMinOpen);
    if (resultFilterCaps.length)
      base = base.filter((r) => {
        const caps = capabilityFlags(r);
        return resultFilterCaps.every((id) => caps[id]);
      });
    return [...base].sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9));
  }, [
    currentBatch,
    mergedResults,
    resultFilterCaps,
    resultFilterMinOpen,
    resultFilterQuery,
    resultFilterStatus,
    resultOnlyLastBatch,
  ]);

  const openPortsDist = useMemo(() => {
    const map = new Map<number, number>();
    for (const r of filteredResults)
      map.set(r.openPorts, (map.get(r.openPorts) ?? 0) + 1);
    return [...map.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([openPorts, count]) => ({ openPorts, count }));
  }, [filteredResults]);

  const fastestIps = useMemo(() => {
    return filteredResults
      .filter((r) => r.overall === "success" && r.latency != null)
      .slice(0, 12);
  }, [filteredResults]);

  const capabilityDist = useMemo(() => {
    const acc = new Map<CapabilityId, number>([
      ["cdn", 0],
      ["tunnel", 0],
      ["warp", 0],
      ["bpb", 0],
    ]);
    for (const r of filteredResults) {
      const caps = capabilityFlags(r);
      (Object.keys(acc) as CapabilityId[]).forEach((k) => {
        if (caps[k]) acc.set(k, (acc.get(k) ?? 0) + 1);
      });
    }
    return (["cdn", "tunnel", "warp", "bpb"] as const).map((k) => ({
      name: k.toUpperCase(),
      count: acc.get(k) ?? 0,
    }));
  }, [filteredResults]);

  const portSuccessDist = useMemo(() => {
    const ports = [80, 443, 2053, 8443, 7844, 8080, 2408];
    return ports.map((port) => ({
      port,
      success: filteredResults.filter((r) => l4Status(r, port) === "success")
        .length,
      total: filteredResults.length,
    }));
  }, [filteredResults]);

  const latencyBuckets = useMemo(() => {
    // Buckets in ms for usefulness
    const buckets = [50, 100, 200, 400, 800, 1500, 3000];
    const counts = new Map<string, number>();
    const labelFor = (ms: number | null) => {
      if (ms == null) return "n/a";
      for (const b of buckets) if (ms <= b) return `<=${b}`;
      return `>${buckets[buckets.length - 1]}`;
    };
    for (const r of filteredResults) {
      const k = labelFor(r.latency);
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    const order = [
      "<=50",
      "<=100",
      "<=200",
      "<=400",
      "<=800",
      "<=1500",
      "<=3000",
      `>${buckets[buckets.length - 1]}`,
      "n/a",
    ];
    return order
      .filter((k) => counts.has(k))
      .map((k) => ({ bucket: k, count: counts.get(k) ?? 0 }));
  }, [filteredResults]);

  const progress =
    currentBatch && currentBatch.totalIps > 0
      ? Math.round((currentBatch.scannedCount / currentBatch.totalIps) * 100)
      : 0;

  function toggleRange(range: string): void {
    setSelectedRanges((prev) =>
      prev.includes(range) ? prev.filter((r) => r !== range) : [...prev, range],
    );
  }

  function rangeSelectAllVisible(): void {
    const visible = pagedRanges;
    setSelectedRanges((prev) => {
      const set = new Set(prev);
      const allOn = visible.every((r) => set.has(r));
      if (allOn) visible.forEach((r) => set.delete(r));
      else visible.forEach((r) => set.add(r));
      return [...set];
    });
  }

  function clearLogs(): void {
    setLogs([]);
    toast.success("Logs cleared");
  }

  function clearResults(): void {
    setLiveResults([]);
    setAllResults([]);
    setCurrentBatch(null);
    toast.success("Results cleared");
    pushLog("info", "Results cleared");
  }

  async function addSource(): Promise<void> {
    if (!sourceName.trim() || !sourceUrl.trim()) {
      toast.error("Add source name + URL");
      pushLog("warn", "Source add rejected: missing name or URL");
      return;
    }

    try {
      const url = new URL(sourceUrl.trim());
      const item: SourceItem = {
        id: crypto.randomUUID(),
        name: sourceName.trim(),
        url: url.toString(),
        ranges: [],
        lastFetched: null,
        group: sourceGroup,
      };
      setSources((prev) => [item, ...prev]);
      setSourceName("");
      setSourceUrl("");
      setSourceGroup("custom");
      toast.success("Source added");
      pushLog("ok", `Added source "${item.name}"`);
    } catch {
      toast.error("Invalid URL");
      pushLog("error", `Source add failed: invalid URL "${sourceUrl}"`);
    }
  }

  async function fetchSource(source: SourceItem): Promise<void> {
    try {
      const response = await fetch(source.url);
      const contentType = response.headers.get("content-type") || "";
      const payload: unknown = contentType.includes("application/json")
        ? await response.json()
        : await response.text();
      const cidrs = extractCidrs(payload);

      if (!cidrs.length) {
        toast.error(`No valid CIDR ranges in ${source.name}`);
        pushLog("warn", `No CIDR ranges found from source ${source.name}`);
        return;
      }

      setRanges((prev) => [...new Set([...prev, ...cidrs])]);
      setSources((prev) =>
        prev.map((s) =>
          s.id === source.id
            ? { ...s, ranges: cidrs, lastFetched: new Date().toISOString() }
            : s,
        ),
      );
      toast.success(`Fetched ${cidrs.length} ranges from ${source.name}`);
      pushLog("ok", `Fetched ${cidrs.length} ranges from ${source.name}`);
      setRangeGroup("all");
      setRangePage(1);
    } catch {
      toast.error(`Fetch failed for ${source.name}`);
      pushLog("error", `Source fetch failed: ${source.name}`);
    }
  }

  async function startScan(): Promise<void> {
    if (!selectedRanges.length) {
      toast.error("Select at least one CIDR range");
      pushLog("warn", "Start scan blocked: no ranges selected");
      return;
    }

    const ports = [...new Set(portToggles)]
      .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
      .sort((a, b) => a - b);
    if (!ports.length) {
      toast.error("Select at least one port");
      pushLog("warn", "Start scan blocked: no ports selected");
      return;
    }

    setIsScanning(true);
    setLiveResults([]);
    runRef.current = true;
    abortersRef.current = [];
    pushLog(
      "info",
      `Starting L4 scan on ports [${ports.join(", ")}] for ${selectedRanges.length} ranges`,
    );

    const startedAt = Date.now();
    const targets = selectedRanges.flatMap((range) =>
      sampleCidr(range, ipsPerRange, sampleMode).map((ip) => ({ ip, range })),
    );

    if (!targets.length) {
      toast.error("No testable IPs from selection");
      setIsScanning(false);
      pushLog("warn", "No testable IPs generated from selected CIDRs");
      return;
    }

    const batchId = crypto.randomUUID();
    const baseBatch: ScanBatch = {
      id: batchId,
      name: `Scan ${new Date().toLocaleString()}`,
      createdAt: new Date().toISOString(),
      status: "running",
      totalIps: targets.length,
      scannedCount: 0,
      successCount: 0,
      failedCount: 0,
      ipRanges: [...selectedRanges],
    };

    setCurrentBatch(baseBatch);

    let scanned = 0;
    let success = 0;
    let failed = 0;
    const resultsBuffer: ScanResult[] = [];

    const workerCount = Math.max(1, Math.min(100, scanWorkers)); // keep it sane; backend opens sockets
    let nextIndex = 0;

    const runOne = async (target: { ip: string; range: string }) => {
      if (!runRef.current) return;

      const controller = new AbortController();
      abortersRef.current.push(controller);

      try {
        const probe = await probeIp(apiBaseUrl, target.ip, ports, controller.signal);
        const tcp80 = probe.l4.find((t) => t.port === 80)?.status || "failed";
        const tcp443 = probe.l4.find((t) => t.port === 443)?.status || "failed";
        const tcp2053 =
          probe.l4.find((t) => t.port === 2053)?.status || "failed";
        const tcp8443 =
          probe.l4.find((t) => t.port === 8443)?.status || "failed";
        const openPorts = probe.l4.filter((p) => p.status === "success").length;
        const latency =
          probe.l4.find((t) => t.status === "success")?.latency ||
          probe.l4[0]?.latency ||
          null;

        const result: ScanResult = {
          id: crypto.randomUUID(),
          batchId,
          ipAddress: target.ip,
          ipRange: target.range,
          overall: probe.overall,
          l4: probe.l4,
          tcp80,
          tcp443,
          tcp2053,
          tcp8443,
          openPorts,
          latency,
          createdAt: new Date().toISOString(),
        };

        resultsBuffer.push(result);
        setLiveResults((prev) => [result, ...prev].slice(0, 2000));
        pushLog(
          probe.overall === "success" ? "ok" : "error",
          `${target.ip} => ${probe.overall.toUpperCase()} (${openPorts}/${probe.l4.length} open ports)`,
        );

        if (probe.overall === "success") success += 1;
        else failed += 1;
      } catch (e) {
        // AbortError = user hit Stop
        failed += 1;
        const name = (e as { name?: string } | null)?.name;
        if (name === "AbortError") {
          pushLog("warn", `${target.ip} => aborted`);
        } else {
          pushLog("error", `${target.ip} => probe failed (API/network error)`);
        }
      } finally {
        scanned += 1;
        setCurrentBatch((prev) =>
          prev
            ? {
                ...prev,
                scannedCount: scanned,
                successCount: success,
                failedCount: failed,
              }
            : prev,
        );
      }
    };

    const workerLoop = async () => {
      while (runRef.current) {
        const i = nextIndex;
        nextIndex += 1;
        if (i >= targets.length) break;
        await runOne(targets[i]);
      }
    };

    await Promise.all(Array.from({ length: workerCount }, workerLoop));

    const finalStatus: BatchStatus =
      runRef.current && scanned >= targets.length ? "completed" : "cancelled";
    const doneBatch: ScanBatch = {
      ...(currentBatch || baseBatch),
      status: finalStatus,
      scannedCount: scanned,
      successCount: success,
      failedCount: failed,
      durationMs: Date.now() - startedAt,
    };

    setHistory((prev) => [doneBatch, ...prev].slice(0, 120));
    setAllResults((prev) => [...resultsBuffer, ...prev].slice(0, 6000));
    setCurrentBatch(doneBatch);
    setIsScanning(false);
    runRef.current = false;

    if (finalStatus === "completed") {
      toast.success(`Completed: ${success} success, ${failed} failed`);
      pushLog("ok", `Scan complete: ${success} success / ${failed} failed`);
    } else {
      toast.warning("Scan cancelled");
      pushLog("warn", "Scan cancelled by user");
    }
  }

  async function vlessRetest(): Promise<void> {
    if (!currentBatch) {
      toast.error("Run a scan first");
      return;
    }
    if (!vlessSettings.uuid.trim()) {
      toast.error("UUID required");
      return;
    }
    if (!vlessSettings.sni.trim() || !vlessSettings.host.trim()) {
      toast.error("SNI + Host required");
      return;
    }
    const port = Math.max(1, Math.min(65535, Number(vlessSettings.port) || 443));
    const topN = Math.max(1, Math.min(200, Number(vlessSettings.topN) || 20));
    const conc = Math.max(
      1,
      Math.min(100, Number(vlessSettings.concurrency) || 20),
    );

    const candidates = currentBatchResults
      .filter((r) => r.overall === "success")
      .sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9))
      .slice(0, topN)
      .map((r) => r.ipAddress);

    if (!candidates.length) {
      toast.error("No valid IPs in last scan");
      return;
    }

    setVlessIsTesting(true);
    setVlessResults([]);
    pushLog("info", `VLESS retest: ${candidates.length} IPs on TCP:${port}`);

    let idx = 0;
    const out: VlessRetestResult[] = [];
    const worker = async () => {
      while (true) {
        const i = idx;
        idx += 1;
        if (i >= candidates.length) return;
        const ip = candidates[i];
        try {
          const probe = await probeIp(apiBaseUrl, ip, [port]);
          const st = probe.l4[0]?.status || probe.overall;
          const lat = probe.l4[0]?.latency ?? null;
          out.push({ ip, port, status: st, latency: lat });
        } catch {
          out.push({ ip, port, status: "failed", latency: null });
        }
      }
    };

    await Promise.all(Array.from({ length: conc }, worker));

    out.sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9));
    setVlessResults(out);
    setVlessIsTesting(false);
    const ok = out.filter((r) => r.status === "success").length;
    toast.success(`VLESS retest done: ${ok}/${out.length} ok`);
    pushLog("ok", `VLESS retest done: ${ok}/${out.length} ok`);
  }

  function stopScan(): void {
    runRef.current = false;
    abortersRef.current.forEach((c) => c.abort());
    pushLog("warn", "Stop requested by user");
  }

  function rerun(batch: ScanBatch): void {
    setSelectedRanges(batch.ipRanges);
    setActiveTab("scanner");
    toast.info("Scan preset loaded");
    pushLog("info", `Loaded previous batch: ${batch.name}`);
  }

  const tabs: Array<{ id: Tab; label: string; icon: ReactNode }> = [
    { id: "scanner", label: "Scanner", icon: <Radar size={14} /> },
    { id: "sources", label: "Sources", icon: <Database size={14} /> },
    { id: "history", label: "History", icon: <RefreshCw size={14} /> },
    { id: "results", label: "Results", icon: <Wifi size={14} /> },
    { id: "analytics", label: "Analytics", icon: <Gauge size={14} /> },
    { id: "export", label: "Export", icon: <Download size={14} /> },
    { id: "dns", label: "DNS", icon: <Shield size={14} /> },
    { id: "vless", label: "VLESS", icon: <Activity size={14} /> },
  ];

  const currentBatchResults = useMemo(() => {
    if (!currentBatch) return [];
    return mergedResults.filter((r) => r.batchId === currentBatch.id);
  }, [currentBatch, mergedResults]);

  const validIpsLastBatch = useMemo(() => {
    if (!currentBatch) return [];
    return currentBatchResults
      .filter((r) => r.overall === "success")
      .map((r) => r.ipAddress);
  }, [currentBatch, currentBatchResults]);

  const validIpsAll = useMemo(() => {
    const set = new Set<string>();
    for (const r of mergedResults)
      if (r.overall === "success") set.add(r.ipAddress);
    return [...set];
  }, [mergedResults]);

  const summary = useMemo(() => {
    if (!currentBatch) return null;
    const portsOpenAvg =
      currentBatchResults.length > 0
        ? Math.round(
            currentBatchResults.reduce((acc, r) => acc + r.openPorts, 0) /
              currentBatchResults.length,
          )
        : 0;
    return {
      status: currentBatch.status,
      total: currentBatch.totalIps,
      scanned: currentBatch.scannedCount,
      success: currentBatch.successCount,
      failed: currentBatch.failedCount,
      durationMs: currentBatch.durationMs ?? null,
      portsOpenAvg,
    };
  }, [currentBatch, currentBatchResults]);

  function exportValidIps(
    format: ExportFormat,
    scope: "last" | "all",
    filenameBase: string,
  ): void {
    const ips = scope === "last" ? validIpsLastBatch : validIpsAll;
    const rows: ExportRow[] = ips.map((ip) => ({ ip }));
    exportRows(format, rows, filenameBase);
  }

  function exportResultsTable(
    format: ExportFormat,
    rows: ScanResult[],
    filenameBase: string,
  ): void {
    const tableRows: ExportRow[] = rows.map((r) => ({
      cdn: capabilityFlags(r).cdn ? 1 : 0,
      tunnel: capabilityFlags(r).tunnel ? 1 : 0,
      warp_tcp_heuristic: capabilityFlags(r).warp ? 1 : 0,
      bpb: capabilityFlags(r).bpb ? 1 : 0,
      ip: r.ipAddress,
      range: r.ipRange,
      overall: r.overall,
      tcp_80: r.tcp80,
      tcp_443: r.tcp443,
      tcp_2053: r.tcp2053,
      tcp_8443: r.tcp8443,
      open_ports: r.openPorts,
      latency_ms: r.latency,
      time: r.createdAt,
    }));
    exportRows(format, tableRows, filenameBase);
  }

  function exportCapabilityIpsTxt(cap: CapabilityId, filenameBase: string): void {
    if (!currentBatch) {
      toast.error("No last scan to export");
      return;
    }
    const rows = currentBatchResults
      .filter((r) => r.overall === "success")
      .filter((r) => capabilityFlags(r)[cap])
      .map((r) => ({ ip: r.ipAddress }));
    exportRows("txt", rows, filenameBase);
  }

  const dnsCandidateIps = useMemo(() => {
    if (!currentBatch) return [];
    const base = currentBatchResults.filter((r) => r.overall === "success");
    const filtered =
      dnsSettings.includeCaps.length === 0
        ? base
        : base.filter((r) => {
            const caps = capabilityFlags(r);
            return dnsSettings.includeCaps.every((c) => caps[c]);
          });
    // Already sorted by latency in filteredResults, but here we re-sort to be explicit.
    return [...filtered]
      .sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9))
      .map((r) => r.ipAddress);
  }, [currentBatch, currentBatchResults, dnsSettings.includeCaps]);

  async function applyDns(): Promise<void> {
    if (!currentBatch) {
      toast.error("Run a scan first");
      return;
    }
    const token = dnsSettings.token.trim();
    const zoneId = dnsSettings.zoneId.trim();
    const name = dnsSettings.recordName.trim();
    if (!token) return void toast.error("Cloudflare API token required");
    if (!zoneId) return void toast.error("Zone ID required");
    if (!name || !name.includes(".")) return void toast.error("Record name invalid");

    const n = Math.max(1, Math.min(50, dnsSettings.topN || 1));
    const ips = dnsCandidateIps.slice(0, n);
    if (!ips.length) return void toast.error("No IPs matched your filters");

    try {
      pushLog("info", `Cloudflare DNS replace: ${name} => ${ips.length} A records`);
      const out = await cfReplaceARecords({
        apiBaseUrl,
        token,
        zoneId,
        name,
        ips,
        proxied: dnsSettings.proxied,
        ttl: dnsSettings.ttl,
      });
      if (out.ok) {
        toast.success(`DNS updated: ${name} (${ips.length} A records)`);
        pushLog("ok", `DNS updated: ${name} (${ips.length} A records)`);
      } else {
        toast.error(out.error || "DNS update failed");
        pushLog("error", `DNS update failed: ${out.error || "unknown error"}`);
      }
    } catch (e) {
      toast.error((e as Error).message || "DNS update failed");
      pushLog("error", `DNS update failed: ${(e as Error).message || "unknown"}`);
    }
  }

  function downloadProxyConfigs(kind: "xray" | "singbox" | "clash_yaml" | "clash_json"): void {
    if (!currentBatch) {
      toast.error("No last scan to export");
      return;
    }
    if (!proxyExport.secret.trim()) {
      toast.error(proxyExport.protocol === "trojan_ws_tls" ? "Password required" : "UUID required");
      return;
    }
    if (!proxyExport.sni.trim() || !proxyExport.host.trim()) {
      toast.error("SNI + Host required");
      return;
    }
    const preferredPorts = parsePreferredPorts(proxyExport.preferredPortsCsv);
    const base = currentBatchResults.filter((r) => r.overall === "success");
    const filtered =
      proxyExport.includeCaps.length === 0
        ? base
        : base.filter((r) => {
            const caps = capabilityFlags(r);
            return proxyExport.includeCaps.every((c) => caps[c]);
          });

    const nodes = filtered
      .map((r) => ({ r, port: pickOpenPort(r, preferredPorts) }))
      .filter((x): x is { r: ScanResult; port: number } => typeof x.port === "number");

    if (!nodes.length) {
      toast.error("No nodes matched filter/ports");
      return;
    }

    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const proto = proxyExport.protocol;
    const sni = proxyExport.sni.trim();
    const host = proxyExport.host.trim();
    const path = proxyExport.path.trim() || "/";
    const secret = proxyExport.secret.trim();

    if (kind === "singbox") {
      const outbounds = nodes.map(({ r, port }) => {
        const tag = `${r.ipAddress}:${port}`;
        if (proto === "trojan_ws_tls") {
          return {
            type: "trojan",
            tag,
            server: r.ipAddress,
            server_port: port,
            password: secret,
            tls: { enabled: true, server_name: sni, insecure: false },
            transport: { type: "ws", path, headers: { Host: host } },
          };
        }
        return {
          type: "vless",
          tag,
          server: r.ipAddress,
          server_port: port,
          uuid: secret,
          tls: { enabled: true, server_name: sni, insecure: false },
          transport: { type: "ws", path, headers: { Host: host } },
        };
      });

      const selectorTag = "Proxy";
      const config = {
        log: { level: "warn" },
        inbounds: [
          { type: "socks", tag: "socks-in", listen: "127.0.0.1", listen_port: 10808 },
          { type: "http", tag: "http-in", listen: "127.0.0.1", listen_port: 10809 },
        ],
        outbounds: [
          {
            type: "selector",
            tag: selectorTag,
            outbounds: outbounds.map((o) => o.tag),
            default: outbounds[0]?.tag,
          },
          ...outbounds,
          { type: "direct", tag: "direct" },
          { type: "block", tag: "block" },
        ],
        route: {
          rules: [
            { inbound: ["socks-in", "http-in"], outbound: selectorTag },
          ],
        },
      };

      downloadBlob(
        new Blob([JSON.stringify(config, null, 2)], { type: "application/json" }),
        `crimsoncf_sing-box_${proto}_${ts}.json`,
      );
      return;
    }

    if (kind === "xray") {
      const outbounds = nodes.map(({ r, port }) => {
        const tag = `${r.ipAddress}:${port}`;
        const baseStream = {
          network: "ws",
          security: "tls",
          tlsSettings: { serverName: sni, allowInsecure: false },
          wsSettings: { path, headers: { Host: host } },
        };
        if (proto === "trojan_ws_tls") {
          return {
            tag,
            protocol: "trojan",
            settings: { servers: [{ address: r.ipAddress, port, password: secret }] },
            streamSettings: baseStream,
          };
        }
        return {
          tag,
          protocol: "vless",
          settings: {
            vnext: [
              {
                address: r.ipAddress,
                port,
                users: [{ id: secret, encryption: "none" }],
              },
            ],
          },
          streamSettings: baseStream,
        };
      });

      const balancerTag = "crimsoncf-auto";
      const config = {
        log: { loglevel: "warning" },
        inbounds: [
          {
            port: 10808,
            listen: "127.0.0.1",
            protocol: "socks",
            settings: { udp: true },
          },
          { port: 10809, listen: "127.0.0.1", protocol: "http" },
        ],
        outbounds: [
          ...outbounds,
          { tag: "direct", protocol: "freedom" },
          { tag: "block", protocol: "blackhole" },
        ],
        routing: {
          domainStrategy: "AsIs",
          balancers: [
            {
              tag: balancerTag,
              selector: outbounds.map((o) => o.tag),
              strategy: { type: "random" },
            },
          ],
          rules: [{ type: "field", balancerTag }],
        },
      };

      downloadBlob(
        new Blob([JSON.stringify(config, null, 2)], { type: "application/json" }),
        `crimsoncf_xray_${proto}_${ts}.json`,
      );
      return;
    }

    // Clash Meta oriented output.
    const clashProxies = nodes.map(({ r, port }) => {
      const name = `CF ${r.ipAddress}:${port}`;
      if (proto === "trojan_ws_tls") {
        return {
          name,
          type: "trojan",
          server: r.ipAddress,
          port,
          password: secret,
          udp: true,
          sni,
          "skip-cert-verify": false,
          network: "ws",
          "ws-opts": { path, headers: { Host: host } },
        };
      }
      return {
        name,
        type: "vless",
        server: r.ipAddress,
        port,
        uuid: secret,
        udp: true,
        tls: true,
        servername: sni,
        network: "ws",
        "ws-opts": { path, headers: { Host: host } },
      };
    });

    const clash = {
      port: 7890,
      "socks-port": 7891,
      "allow-lan": true,
      mode: "rule",
      "log-level": "info",
      proxies: clashProxies,
      "proxy-groups": [
        {
          name: "Proxy",
          type: "select",
          proxies: ["Auto", ...clashProxies.map((p) => p.name)],
        },
        {
          name: "Auto",
          type: "url-test",
          url: "http://www.gstatic.com/generate_204",
          interval: 300,
          tolerance: 50,
          proxies: clashProxies.map((p) => p.name),
        },
      ],
      rules: ["MATCH,Proxy"],
    };

    if (kind === "clash_json") {
      downloadBlob(
        new Blob([JSON.stringify(clash, null, 2)], { type: "application/json" }),
        `crimsoncf_clash_${proto}_${ts}.json`,
      );
      return;
    }

    const lines: string[] = [];
    const pushKV = (k: string, v: unknown, indent = 0) => {
      const pad = "  ".repeat(indent);
      if (typeof v === "string") lines.push(`${pad}${k}: ${yamlEscape(v)}`);
      else if (typeof v === "number" || typeof v === "boolean")
        lines.push(`${pad}${k}: ${String(v)}`);
      else if (Array.isArray(v)) {
        lines.push(`${pad}${k}:`);
        for (const item of v) {
          if (item && typeof item === "object") {
            lines.push(`${pad}-`);
            Object.entries(item as Record<string, unknown>).forEach(([kk, vv]) =>
              pushKV(kk, vv, indent + 1),
            );
          } else {
            lines.push(`${pad}- ${yamlEscape(String(item))}`);
          }
        }
      } else if (v && typeof v === "object") {
        lines.push(`${pad}${k}:`);
        Object.entries(v as Record<string, unknown>).forEach(([kk, vv]) =>
          pushKV(kk, vv, indent + 1),
        );
      } else {
        lines.push(`${pad}${k}: null`);
      }
    };

    Object.entries(clash as Record<string, unknown>).forEach(([k, v]) => pushKV(k, v, 0));
    const yaml = lines.join("\n");
    downloadBlob(
      new Blob([yaml], { type: "text/yaml" }),
      `crimsoncf_clash_${proto}_${ts}.yaml`,
    );
  }

  return (
    <div className="ui-root">
      <Toaster theme="dark" richColors position="top-right" />

      <div className="bg-glow g1" />
      <div className="bg-glow g2" />
      <div className="grid-overlay" />

      <div className="page-wrap">
        <motion.header
          className="hero"
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div>
            <div className="brand-row">
              <img className="brand-mark" src="/icon.svg" alt="CrimsonCF" />
              <p className="eyebrow">CrimsonCF</p>
            </div>
            <h1>
              <span>CRIMSON</span> CF SCANNER
            </h1>
            <p className="sub">
              L4 TCP handshake probing with persistent history, sources and live
              charts.
            </p>
          </div>

          <div className="hero-actions">
            <button
              className="btn ghost"
              onClick={() => setRanges(DEFAULT_RANGES)}
              type="button"
            >
              <Cloud size={15} /> Reset Cloudflare
            </button>
            {isScanning ? (
              <button className="btn danger" onClick={stopScan} type="button">
                <Square size={14} /> Stop
              </button>
            ) : (
              <button
                className="btn primary"
                onClick={startScan}
                type="button"
                disabled={!selectedRanges.length}
              >
                <Play size={14} /> Start Scan
              </button>
            )}
          </div>
        </motion.header>

        <section className="stats-grid">
          {[
            {
              label: "Total Ranges",
              value: ranges.length,
              icon: <Database size={16} />,
            },
            {
              label: "Selected",
              value: selectedRanges.length,
              icon: <Shield size={16} />,
            },
            {
              label: "Success Rate",
              value:
                mergedResults.length > 0
                  ? `${Math.round((stats.success / mergedResults.length) * 100)}%`
                  : "0%",
              icon: <Activity size={16} />,
            },
            {
              label: "Results",
              value: mergedResults.length,
              icon: <Wifi size={16} />,
            },
          ].map((s, index) => (
            <motion.article
              key={s.label}
              className="stat-card"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <div className="stat-icon">{s.icon}</div>
              <p>{s.label}</p>
              <h3>{s.value}</h3>
            </motion.article>
          ))}
        </section>

        <section className="main-panel">
          <div className="top-controls">
            <label>
              IPs per range
              <input
                type="number"
                min={1}
                max={50}
                value={ipsPerRange}
                onChange={(e) =>
                  setIpsPerRange(
                    Math.max(1, Math.min(50, Number(e.target.value) || 1)),
                  )
                }
              />
            </label>
            <div className="meta">
              Estimated IPs: {selectedRanges.length * ipsPerRange}
            </div>
            <div className="meta">L4 mode: TCP handshake only</div>
            <label>
              Workers
              <input
                type="number"
                min={1}
                max={100}
                value={scanWorkers}
                onChange={(e) =>
                  setScanWorkers(
                    Math.max(1, Math.min(100, Number(e.target.value) || 1)),
                  )
                }
              />
            </label>
            <label>
              Sampling
              <select
                value={sampleMode}
                onChange={(e) =>
                  setSampleMode(e.target.value as "sequential" | "random")
                }
              >
                <option value="random">random</option>
                <option value="sequential">sequential</option>
              </select>
            </label>
          </div>

          <div className="ports-panel">
            <div className="ports-head">
              <strong>Ports</strong>
              <span className="muted">{portToggles.length} selected</span>
            </div>
            <div className="ports-grid">
              {[80, 443, 7844, 2053, 2083, 2087, 2096, 8443].map((p) => (
                <button
                  key={p}
                  type="button"
                  className={`port-chip ${portToggles.includes(p) ? "on" : ""}`}
                  onClick={() => togglePort(p)}
                >
                  {p}
                </button>
              ))}
              {portToggles
                .filter(
                  (p) =>
                    ![80, 443, 7844, 2053, 2083, 2087, 2096, 8443].includes(p),
                )
                .sort((a, b) => a - b)
                .map((p) => (
                  <button
                    key={p}
                    type="button"
                    className="port-chip on custom"
                    onClick={() => togglePort(p)}
                    title="Click to remove"
                  >
                    {p}
                  </button>
                ))}
            </div>
            <div className="ports-add">
              <input
                type="number"
                min={1}
                max={65535}
                placeholder="Custom port"
                value={customPort}
                onChange={(e) => setCustomPort(e.target.value)}
              />
              <button
                className="btn ghost"
                type="button"
                onClick={addCustomPort}
              >
                Add
              </button>
            </div>
          </div>

          {(currentBatch || isScanning) && (
            <div className="progress-block">
              <div className="progress-head">
                <strong>{currentBatch?.name || "Scanning..."}</strong>
                <span>
                  {currentBatch?.scannedCount || 0}/
                  {currentBatch?.totalIps || 0}
                </span>
              </div>
              <Progress value={progress} />
            </div>
          )}

          {summary && !isScanning && (
            <div className="summary-card">
              <div className="summary-head">
                <strong>Last Scan Summary</strong>
                <span className={`badge ${summary.status}`}>
                  {summary.status}
                </span>
              </div>
              <div className="summary-grid">
                <div>
                  <span>Total</span>
                  <b>{summary.total}</b>
                </div>
                <div>
                  <span>Scanned</span>
                  <b>{summary.scanned}</b>
                </div>
                <div>
                  <span>Success</span>
                  <b>{summary.success}</b>
                </div>
                <div>
                  <span>Failed</span>
                  <b>{summary.failed}</b>
                </div>
                <div>
                  <span>Avg Open Ports</span>
                  <b>{summary.portsOpenAvg}</b>
                </div>
                <div>
                  <span>Duration</span>
                  <b>
                    {summary.durationMs
                      ? `${Math.round(summary.durationMs / 1000)}s`
                      : "-"}
                  </b>
                </div>
              </div>
              <div className="summary-actions">
                <button
                  className="btn ghost"
                  type="button"
                  onClick={clearResults}
                >
                  Clear Results
                </button>
                <button className="btn ghost" type="button" onClick={clearLogs}>
                  Clear Logs
                </button>
                <button
                  className="btn ghost"
                  type="button"
                  onClick={() =>
                    exportValidIps("txt", "last", "crimsoncf_valid_ips_last")
                  }
                >
                  Export Valid (TXT)
                </button>
                <button
                  className="btn ghost"
                  type="button"
                  onClick={() =>
                    exportValidIps("xlsx", "last", "crimsoncf_valid_ips_last")
                  }
                >
                  Export Valid (XLSX)
                </button>
              </div>
            </div>
          )}

          <div className="tabs-row">
            {tabs.map((t) => (
              <button
                key={t.id}
                className={`tab ${activeTab === t.id ? "active" : ""}`}
                onClick={() => setActiveTab(t.id)}
                type="button"
              >
                {t.icon}
                {t.label}
              </button>
            ))}
          </div>

          {activeTab === "scanner" && (
            <div className="panel-block">
              <div className="row-tools">
                <label className="mini-field">
                  Probe API
                  <input
                    value={apiBaseUrl}
                    onChange={(e) => setApiBaseUrl(e.target.value)}
                    placeholder="(same origin) or http://localhost:8787"
                  />
                </label>
                <button
                  className="btn ghost"
                  onClick={() =>
                    setSelectedRanges(
                      selectedRanges.length === ranges.length
                        ? []
                        : [...ranges],
                    )
                  }
                  type="button"
                >
                  {selectedRanges.length === ranges.length
                    ? "Unselect All"
                    : "Select All"}
                </button>
                <button
                  className="btn ghost"
                  onClick={rangeSelectAllVisible}
                  type="button"
                >
                  Select Page
                </button>
                <button
                  className="btn ghost"
                  onClick={() => setSelectedRanges([])}
                  type="button"
                >
                  Clear
                </button>
                <button
                  className="btn ghost"
                  onClick={clearResults}
                  type="button"
                >
                  Clear Results
                </button>
              </div>
              <div className="range-toolbar">
                <div className="range-groups">
                  {(
                    [
                      ["all", "All"],
                      ["cdn", "CDN"],
                      ["tunnel", "Tunnel"],
                      ["warp", "WARP"],
                      ["custom", "Custom"],
                    ] as const
                  ).map(([id, label]) => (
                    <button
                      key={id}
                      type="button"
                      className={rangeGroup === id ? "port-chip on" : "port-chip"}
                      onClick={() => {
                        setRangeGroup(id);
                        setRangePage(1);
                      }}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div className="range-pager">
                  <button
                    type="button"
                    className="btn ghost"
                    disabled={rangePage <= 1}
                    onClick={() => setRangePage((p) => Math.max(1, p - 1))}
                  >
                    Prev
                  </button>
                  <div className="pager-nums">
                    {Array.from({ length: rangeTotalPages })
                      .slice(
                        Math.max(0, rangePage - 3),
                        Math.min(rangeTotalPages, rangePage + 2),
                      )
                      .map((_, i) => {
                        const page = Math.max(1, rangePage - 2) + i;
                        return (
                          <button
                            key={page}
                            type="button"
                            className={page === rangePage ? "port-chip on" : "port-chip"}
                            onClick={() => setRangePage(page)}
                          >
                            {page}
                          </button>
                        );
                      })}
                    {rangeTotalPages > 1 && rangePage < rangeTotalPages - 2 && (
                      <span className="ellipsis">…</span>
                    )}
                    {rangeTotalPages > 5 && (
                      <button
                        type="button"
                        className={rangePage === rangeTotalPages ? "port-chip on" : "port-chip"}
                        onClick={() => setRangePage(rangeTotalPages)}
                      >
                        {rangeTotalPages}
                      </button>
                    )}
                  </div>
                  <button
                    type="button"
                    className="btn ghost"
                    disabled={rangePage >= rangeTotalPages}
                    onClick={() =>
                      setRangePage((p) => Math.min(rangeTotalPages, p + 1))
                    }
                  >
                    Next
                  </button>
                  <label className="mini-field">
                    Page size
                    <select
                      value={rangePageSize}
                      onChange={(e) => {
                        setRangePageSize(Number(e.target.value) || 90);
                        setRangePage(1);
                      }}
                    >
                      <option value={45}>45</option>
                      <option value={90}>90</option>
                      <option value={180}>180</option>
                    </select>
                  </label>
                  <span className="muted">
                    {filteredRanges.length} ranges
                  </span>
                </div>
              </div>
              <div className="cidr-grid">
                {pagedRanges.map((r) => (
                  <button
                    key={r}
                    className={`cidr-chip ${selectedRanges.includes(r) ? "on" : ""}`}
                    onClick={() => toggleRange(r)}
                    type="button"
                  >
                    {r}
                  </button>
                ))}
              </div>

              <section className="terminal-card">
                <div className="terminal-head">
                  <span className="dot red" />
                  <span className="dot yellow" />
                  <span className="dot green" />
                  <strong>Live Probe Log</strong>
                  <div className="terminal-actions">
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={clearLogs}
                    >
                      Clear
                    </button>
                  </div>
                </div>
                <div className="terminal-body">
                  {logs.length === 0 && (
                    <p className="terminal-empty">
                      No logs yet. Start a scan to stream events.
                    </p>
                  )}
                  {logs.map((log) => (
                    <p key={log.id} className={`terminal-line ${log.level}`}>
                      <span>[{log.ts}]</span> {log.text}
                    </p>
                  ))}
                </div>
              </section>
            </div>
          )}

          {activeTab === "sources" && (
            <div className="panel-block">
              <div className="preset-row">
                <button
                  className="btn ghost"
                  type="button"
                  onClick={() => {
                    setSourceName("Cloudflare IPv4 (official)");
                    setSourceUrl("https://www.cloudflare.com/ips-v4");
                    setSourceGroup("cdn");
                    toast.info("Preset loaded (Cloudflare IPv4)");
                  }}
                >
                  Preset: CF IPv4
                </button>
                <button
                  className="btn ghost"
                  type="button"
                  onClick={() => {
                    setSourceName("Cloudflare IPv6 (official)");
                    setSourceUrl("https://www.cloudflare.com/ips-v6");
                    setSourceGroup("cdn");
                    toast.info("Preset loaded (Cloudflare IPv6)");
                  }}
                >
                  Preset: CF IPv6
                </button>
                <button
                  className="btn ghost"
                  type="button"
                  onClick={async () => {
                    if (!sources.length) return void toast.error("No sources to fetch");
                    pushLog("info", `Fetching all sources (${sources.length})`);
                    for (const s of sources) await fetchSource(s);
                  }}
                >
                  Fetch All
                </button>
              </div>
              <div className="source-form">
                <input
                  placeholder="Source name"
                  value={sourceName}
                  onChange={(e) => setSourceName(e.target.value)}
                />
                <input
                  placeholder="https://example.com/list.txt or api endpoint"
                  value={sourceUrl}
                  onChange={(e) => setSourceUrl(e.target.value)}
                />
                <select
                  value={sourceGroup}
                  onChange={(e) =>
                    setSourceGroup(e.target.value as SourceGroupId)
                  }
                >
                  <option value="custom">custom</option>
                  <option value="cdn">cdn</option>
                  <option value="tunnel">tunnel</option>
                  <option value="warp">warp</option>
                </select>
                <button
                  className="btn primary"
                  onClick={addSource}
                  type="button"
                >
                  Add
                </button>
              </div>

              <div className="source-list">
                {!sources.length && (
                  <p className="empty">No custom sources yet.</p>
                )}
                {sources.map((s) => (
                  <article key={s.id} className="source-item">
                    <div>
                      <h4>{s.name}</h4>
                      <p>{s.url}</p>
                      <small>
                        {s.lastFetched
                          ? `Last fetched: ${new Date(s.lastFetched).toLocaleString()}`
                          : "Never fetched"}
                      </small>
                      <small>Group: {s.group || "custom"}</small>
                    </div>
                    <div className="source-actions">
                      <select
                        value={s.group || "custom"}
                        onChange={(e) =>
                          setSources((prev) =>
                            prev.map((x) =>
                              x.id === s.id
                                ? {
                                    ...x,
                                    group: e.target.value as SourceGroupId,
                                  }
                                : x,
                            ),
                          )
                        }
                      >
                        <option value="custom">custom</option>
                        <option value="cdn">cdn</option>
                        <option value="tunnel">tunnel</option>
                        <option value="warp">warp</option>
                      </select>
                      <button
                        className="btn ghost"
                        onClick={() => fetchSource(s)}
                        type="button"
                      >
                        Fetch
                      </button>
                      <button
                        className="btn danger"
                        onClick={() =>
                          setSources((prev) =>
                            prev.filter((x) => x.id !== s.id),
                          )
                        }
                        type="button"
                      >
                        Remove
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          )}

          {activeTab === "history" && (
            <div className="panel-block">
              <div className="search-row">
                <div className="search-wrap">
                  <Search size={14} />
                  <input
                    placeholder="Search by name or range"
                    value={historyQuery}
                    onChange={(e) => setHistoryQuery(e.target.value)}
                  />
                </div>
                <input
                  type="date"
                  value={historyDate}
                  onChange={(e) => setHistoryDate(e.target.value)}
                />
              </div>

              <div className="history-list">
                {!historyFiltered.length && (
                  <p className="empty">No scan history</p>
                )}
                {historyFiltered.map((h) => (
                  <article key={h.id} className="history-item">
                    <div className="line1">
                      <div>
                        <h4>{h.name}</h4>
                        <small>{new Date(h.createdAt).toLocaleString()}</small>
                      </div>
                      <span className={`badge ${h.status}`}>{h.status}</span>
                    </div>
                    <div className="line2">
                      <span>Total {h.totalIps}</span>
                      <span>Success {h.successCount}</span>
                      <span>Failed {h.failedCount}</span>
                    </div>
                    <Progress
                      value={
                        h.totalIps
                          ? Math.round((h.successCount / h.totalIps) * 100)
                          : 0
                      }
                    />
                    <div className="line3">
                      <small>{h.ipRanges.slice(0, 3).join(" · ")}</small>
                      <div className="history-actions">
                        <button
                          className="btn ghost"
                          onClick={() => rerun(h)}
                          type="button"
                        >
                          Re-run
                        </button>
                        <button
                          className="btn ghost"
                          onClick={() => {
                            const batchResults = mergedResults.filter(
                              (r) =>
                                r.batchId === h.id && r.overall === "success",
                            );
                            exportRows(
                              "txt",
                              batchResults.map((r) => ({ ip: r.ipAddress })),
                              `crimsoncf_valid_ips_${h.id}`,
                            );
                          }}
                          type="button"
                        >
                          Export Valid
                        </button>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          )}

          {activeTab === "results" && (
            <div className="panel-block">
              <div className="results-filters">
                <div className="search-wrap">
                  <Search size={14} />
                  <input
                    placeholder="Filter by IP or range..."
                    value={resultFilterQuery}
                    onChange={(e) => setResultFilterQuery(e.target.value)}
                  />
                </div>
                <label>
                  Status
                  <select
                    value={resultFilterStatus}
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v === "all" || v === "success" || v === "failed")
                        setResultFilterStatus(v);
                    }}
                  >
                    <option value="all">all</option>
                    <option value="success">success</option>
                    <option value="failed">failed</option>
                  </select>
                </label>
                <label>
                  Min open ports
                  <input
                    type="number"
                    min={0}
                    max={20}
                    value={resultFilterMinOpen}
                    onChange={(e) =>
                      setResultFilterMinOpen(
                        Math.max(0, Number(e.target.value) || 0),
                      )
                    }
                  />
                </label>
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={resultOnlyLastBatch}
                    onChange={(e) => setResultOnlyLastBatch(e.target.checked)}
                  />
                  Only last scan
                </label>
                <div className="caps-filter">
                  <span className="caps-label">Capabilities</span>
                  <div className="caps-pills">
                    {(
                      [
                        ["cdn", "CDN"],
                        ["tunnel", "Tunnel"],
                        ["warp", "WARP*"],
                        ["bpb", "BPB"],
                      ] as const
                    ).map(([id, label]) => (
                      <button
                        key={id}
                        type="button"
                        className={
                          resultFilterCaps.includes(id)
                            ? "port-chip on"
                            : "port-chip"
                        }
                        onClick={() =>
                          setResultFilterCaps((prev) =>
                            prev.includes(id)
                              ? prev.filter((x) => x !== id)
                              : [...prev, id],
                          )
                        }
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <button
                  className="btn ghost"
                  type="button"
                  onClick={() =>
                    exportResultsTable(
                      "xlsx",
                      filteredResults,
                      "crimsoncf_results_table",
                    )
                  }
                >
                  Export Table (XLSX)
                </button>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>CDN</th>
                      <th>Tunnel</th>
                      <th>WARP*</th>
                      <th>BPB</th>
                      <th>IP</th>
                      <th>Range</th>
                      <th>Overall</th>
                      <th>TCP:80</th>
                      <th>TCP:443</th>
                      <th>TCP:2053</th>
                      <th>TCP:8443</th>
                      <th>Open Ports</th>
                      <th>Latency</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResults.slice(0, 500).map((r) => {
                      const caps = capabilityFlags(r);
                      return (
                        <tr key={r.id}>
                          <td className={caps.cdn ? "cap yes" : "cap no"}>
                            {caps.cdn ? "yes" : "no"}
                          </td>
                          <td className={caps.tunnel ? "cap yes" : "cap no"}>
                            {caps.tunnel ? "yes" : "no"}
                          </td>
                          <td className={caps.warp ? "cap yes" : "cap no"}>
                            {caps.warp ? "yes" : "no"}
                          </td>
                          <td className={caps.bpb ? "cap yes" : "cap no"}>
                            {caps.bpb ? "yes" : "no"}
                          </td>
                          <td>{r.ipAddress}</td>
                          <td>{r.ipRange}</td>
                          <td className={`st ${r.overall}`}>{r.overall}</td>
                          <td className={`st ${r.tcp80}`}>{r.tcp80}</td>
                          <td className={`st ${r.tcp443}`}>{r.tcp443}</td>
                          <td className={`st ${r.tcp2053}`}>{r.tcp2053}</td>
                          <td className={`st ${r.tcp8443}`}>{r.tcp8443}</td>
                          <td>{r.openPorts}</td>
                          <td>{r.latency ?? "-"}</td>
                          <td>{new Date(r.createdAt).toLocaleTimeString()}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === "analytics" && (
            <div className="analytics-grid">
              <article className="chart-card">
                <h4>Probe Flow</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient
                          id="redFill"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop
                            offset="5%"
                            stopColor="#ff4a4a"
                            stopOpacity={0.8}
                          />
                          <stop
                            offset="95%"
                            stopColor="#ff4a4a"
                            stopOpacity={0}
                          />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" hide />
                      <YAxis stroke="#9a5b5b" />
                      <Tooltip
                        contentStyle={{
                          background: "#130707",
                          border: "1px solid #4d1a1a",
                          color: "#ffd9d9",
                        }}
                      />
                      <Area
                        dataKey="count"
                        type="monotone"
                        stroke="#ff5454"
                        fill="url(#redFill)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Result Distribution</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={pieData}>
                      <XAxis dataKey="name" stroke="#9a5b5b" />
                      <YAxis stroke="#9a5b5b" allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "#130707",
                          border: "1px solid #4d1a1a",
                          color: "#ffd9d9",
                        }}
                      />
                      <Bar dataKey="value" fill="#ff4f4f" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Top Fastest (Filtered)</h4>
                <div className="mini-table">
                  <table>
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Port</th>
                        <th>Latency</th>
                        <th>CDN</th>
                      </tr>
                    </thead>
                    <tbody>
                      {fastestIps.map((r) => {
                        const caps = capabilityFlags(r);
                        const port =
                          r.l4?.find((p) => p.status === "success")?.port ?? "-";
                        return (
                          <tr key={r.id}>
                            <td>{r.ipAddress}</td>
                            <td>{port}</td>
                            <td>{r.latency ?? "-"}</td>
                            <td>{caps.cdn ? "yes" : "no"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </article>
              <article className="chart-card">
                <h4>Latency Buckets (Filtered)</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={latencyBuckets}>
                      <XAxis dataKey="bucket" stroke="#9a5b5b" />
                      <YAxis stroke="#9a5b5b" />
                      <Tooltip
                        contentStyle={{
                          background: "#130707",
                          border: "1px solid #4d1a1a",
                          color: "#ffd9d9",
                        }}
                      />
                      <Bar dataKey="count" fill="#ff4f4f" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Open Ports Distribution (Filtered)</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={openPortsDist}>
                      <XAxis dataKey="openPorts" stroke="#9a5b5b" />
                      <YAxis stroke="#9a5b5b" />
                      <Tooltip
                        contentStyle={{
                          background: "#130707",
                          border: "1px solid #4d1a1a",
                          color: "#ffd9d9",
                        }}
                      />
                      <Bar dataKey="count" fill="#ffb366" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Capabilities (Filtered)</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={capabilityDist}>
                      <XAxis dataKey="name" stroke="#9a5b5b" />
                      <YAxis stroke="#9a5b5b" allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "#130707",
                          border: "1px solid #4d1a1a",
                          color: "#ffd9d9",
                        }}
                      />
                      <Bar dataKey="count" fill="#ffb366" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Per-Port Success (Filtered)</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={portSuccessDist}>
                      <XAxis dataKey="port" stroke="#9a5b5b" />
                      <YAxis stroke="#9a5b5b" allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "#130707",
                          border: "1px solid #4d1a1a",
                          color: "#ffd9d9",
                        }}
                      />
                      <Bar dataKey="success" fill="#ff4f4f" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </article>
            </div>
          )}

          {activeTab === "export" && (
            <div className="panel-block">
              <h3 className="export-title">Export Center</h3>
              <div className="export-grid">
                <article className="export-card">
                  <h4>Valid IPs (Last Scan)</h4>
                  <p>{validIpsLastBatch.length} IPs</p>
                  <div className="export-actions">
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportValidIps(
                          "txt",
                          "last",
                          "crimsoncf_valid_ips_last",
                        )
                      }
                    >
                      TXT
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportValidIps(
                          "json",
                          "last",
                          "crimsoncf_valid_ips_last",
                        )
                      }
                    >
                      JSON
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportValidIps(
                          "xlsx",
                          "last",
                          "crimsoncf_valid_ips_last",
                        )
                      }
                    >
                      XLSX
                    </button>
                  </div>
                </article>

                <article className="export-card">
                  <h4>Valid IPs (All)</h4>
                  <p>{validIpsAll.length} unique IPs</p>
                  <div className="export-actions">
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportValidIps("txt", "all", "crimsoncf_valid_ips_all")
                      }
                    >
                      TXT
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportValidIps(
                          "json",
                          "all",
                          "crimsoncf_valid_ips_all",
                        )
                      }
                    >
                      JSON
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportValidIps(
                          "xlsx",
                          "all",
                          "crimsoncf_valid_ips_all",
                        )
                      }
                    >
                      XLSX
                    </button>
                  </div>
                </article>

                <article className="export-card">
                  <h4>Results Table (Filtered)</h4>
                  <p>{filteredResults.length} rows (sorted by latency)</p>
                  <div className="export-actions">
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportResultsTable(
                          "json",
                          filteredResults,
                          "crimsoncf_results_table_filtered",
                        )
                      }
                    >
                      JSON
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportResultsTable(
                          "xlsx",
                          filteredResults,
                          "crimsoncf_results_table_filtered",
                        )
                      }
                    >
                      XLSX
                    </button>
                  </div>
                </article>

                <article className="export-card">
                  <h4>Capability Lists (Last Scan)</h4>
                  <p>TXT export uses real new lines (one IP per line).</p>
                  <div className="export-actions">
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportCapabilityIpsTxt("cdn", "crimsoncf_cdn_ips_last")
                      }
                    >
                      CDN TXT
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportCapabilityIpsTxt(
                          "tunnel",
                          "crimsoncf_tunnel_ips_last",
                        )
                      }
                    >
                      Tunnel TXT
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportCapabilityIpsTxt(
                          "warp",
                          "crimsoncf_warp_tcp_heuristic_ips_last",
                        )
                      }
                    >
                      WARP* TXT
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() =>
                        exportCapabilityIpsTxt("bpb", "crimsoncf_bpb_ips_last")
                      }
                    >
                      BPB TXT
                    </button>
                  </div>
                </article>

                <article className="export-card">
                  <h4>Xray / sing-box / Clash</h4>
                  <p>Exports use your last scan, filtered by capabilities.</p>
                  <div className="export-form">
                    <label>
                      Protocol
                      <select
                        value={proxyExport.protocol}
                        onChange={(e) =>
                          setProxyExport((p) => ({
                            ...p,
                            protocol: e.target.value as ProxyExportProtocol,
                          }))
                        }
                      >
                        <option value="vless_ws_tls">vless + ws + tls</option>
                        <option value="trojan_ws_tls">trojan + ws + tls</option>
                      </select>
                    </label>
                    <label>
                      {proxyExport.protocol === "trojan_ws_tls"
                        ? "Password"
                        : "UUID"}
                      <input
                        value={proxyExport.secret}
                        onChange={(e) =>
                          setProxyExport((p) => ({ ...p, secret: e.target.value }))
                        }
                        placeholder={
                          proxyExport.protocol === "trojan_ws_tls"
                            ? "trojan password"
                            : "uuid"
                        }
                      />
                    </label>
                    <label>
                      SNI
                      <input
                        value={proxyExport.sni}
                        onChange={(e) =>
                          setProxyExport((p) => ({ ...p, sni: e.target.value }))
                        }
                        placeholder="example.com"
                      />
                    </label>
                    <label>
                      Host
                      <input
                        value={proxyExport.host}
                        onChange={(e) =>
                          setProxyExport((p) => ({ ...p, host: e.target.value }))
                        }
                        placeholder="example.com"
                      />
                    </label>
                    <label>
                      WS Path
                      <input
                        value={proxyExport.path}
                        onChange={(e) =>
                          setProxyExport((p) => ({ ...p, path: e.target.value }))
                        }
                        placeholder="/"
                      />
                    </label>
                    <label>
                      Preferred Ports
                      <input
                        value={proxyExport.preferredPortsCsv}
                        onChange={(e) =>
                          setProxyExport((p) => ({
                            ...p,
                            preferredPortsCsv: e.target.value,
                          }))
                        }
                        placeholder="443,2053,8443,80"
                      />
                    </label>
                    <div className="caps-block">
                      <div className="caps-label">Include only</div>
                      <div className="caps-pills">
                        {(
                          [
                            ["cdn", "CDN"],
                            ["tunnel", "Tunnel"],
                            ["warp", "WARP*"],
                            ["bpb", "BPB"],
                          ] as const
                        ).map(([id, label]) => (
                          <button
                            key={id}
                            type="button"
                            className={
                              proxyExport.includeCaps.includes(id)
                                ? "port-chip on"
                                : "port-chip"
                            }
                            onClick={() =>
                              setProxyExport((p) => ({
                                ...p,
                                includeCaps: p.includeCaps.includes(id)
                                  ? p.includeCaps.filter((x) => x !== id)
                                  : [...p.includeCaps, id],
                              }))
                            }
                          >
                            {label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="export-actions">
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() => downloadProxyConfigs("xray")}
                    >
                      Xray JSON
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() => downloadProxyConfigs("singbox")}
                    >
                      sing-box JSON
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() => downloadProxyConfigs("clash_yaml")}
                    >
                      Clash YAML
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() => downloadProxyConfigs("clash_json")}
                    >
                      Clash JSON
                    </button>
                  </div>
                </article>
              </div>
            </div>
          )}

          {activeTab === "dns" && (
            <div className="panel-block">
              <h3 className="export-title">Cloudflare DNS</h3>
              <p className="empty">
                Replace mode: removes existing A records for this name, then
                creates new A records from the fastest IPs of your last scan.
              </p>

              <div className="export-card">
                <h4>Settings</h4>
                <div className="export-form">
                  <label>
                    API Token
                    <input
                      type="password"
                      value={dnsSettings.token}
                      onChange={(e) =>
                        setDnsSettings((p) => ({ ...p, token: e.target.value }))
                      }
                      placeholder="Cloudflare API Token (DNS Edit)"
                    />
                  </label>
                  <label>
                    Zone ID
                    <input
                      value={dnsSettings.zoneId}
                      onChange={(e) =>
                        setDnsSettings((p) => ({ ...p, zoneId: e.target.value }))
                      }
                      placeholder="zone id"
                    />
                  </label>
                  <label>
                    Record Name
                    <input
                      value={dnsSettings.recordName}
                      onChange={(e) =>
                        setDnsSettings((p) => ({
                          ...p,
                          recordName: e.target.value,
                        }))
                      }
                      placeholder="sub.domain.com"
                    />
                  </label>
                  <label>
                    Top N Fastest
                    <input
                      type="number"
                      min={1}
                      max={50}
                      value={dnsSettings.topN}
                      onChange={(e) =>
                        setDnsSettings((p) => ({
                          ...p,
                          topN: Math.max(1, Math.min(50, Number(e.target.value) || 1)),
                        }))
                      }
                    />
                  </label>
                  <div className="toggle-row">
                    <span className="caps-label">Proxied</span>
                    <button
                      type="button"
                      className={dnsSettings.proxied ? "port-chip on" : "port-chip"}
                      onClick={() =>
                        setDnsSettings((p) => ({ ...p, proxied: !p.proxied }))
                      }
                    >
                      {dnsSettings.proxied ? "ON" : "OFF"}
                    </button>
                  </div>
                  <label>
                    TTL
                    <select
                      value={dnsSettings.ttl}
                      onChange={(e) =>
                        setDnsSettings((p) => ({
                          ...p,
                          ttl: Number(e.target.value) || 1,
                        }))
                      }
                    >
                      <option value={1}>Auto</option>
                      <option value={60}>60s</option>
                      <option value={120}>120s</option>
                      <option value={300}>300s</option>
                    </select>
                  </label>
                  <div className="caps-block">
                    <div className="caps-label">Include only</div>
                    <div className="caps-pills">
                      {(
                        [
                          ["cdn", "CDN"],
                          ["tunnel", "Tunnel"],
                          ["warp", "WARP*"],
                          ["bpb", "BPB"],
                        ] as const
                      ).map(([id, label]) => (
                        <button
                          key={id}
                          type="button"
                          className={
                            dnsSettings.includeCaps.includes(id)
                              ? "port-chip on"
                              : "port-chip"
                          }
                          onClick={() =>
                            setDnsSettings((p) => ({
                              ...p,
                              includeCaps: p.includeCaps.includes(id)
                                ? p.includeCaps.filter((x) => x !== id)
                                : [...p.includeCaps, id],
                            }))
                          }
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="export-actions">
                  <button
                    className="btn primary"
                    type="button"
                    onClick={applyDns}
                  >
                    Apply To Cloudflare DNS
                  </button>
                </div>
              </div>

              <div className="export-card" style={{ marginTop: 10 }}>
                <h4>Preview (Last Scan)</h4>
                <p>
                  {currentBatch ? dnsCandidateIps.length : 0} matched, will use{" "}
                  {currentBatch ? Math.min(dnsSettings.topN, dnsCandidateIps.length) : 0}
                </p>
                <div className="mini-table">
                  <table>
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dnsCandidateIps
                        .slice(0, Math.min(25, Math.max(1, dnsSettings.topN)))
                        .map((ip, i) => (
                          <tr key={ip}>
                            <td>{i + 1}</td>
                            <td>{ip}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === "vless" && (
            <div className="panel-block">
              <h3 className="export-title">VLESS Retest + Builder</h3>
              <p className="empty">
                Paste a VLESS URI or fill fields, then retest your last scan IPs
                on the VLESS port and export clean configs.
              </p>

              <div className="export-card">
                <h4>Input</h4>
                <div className="export-form">
                  <label>
                    VLESS URI (optional)
                    <input
                      value={vlessSettings.vlessUri}
                      onChange={(e) =>
                        setVlessSettings((p) => ({ ...p, vlessUri: e.target.value }))
                      }
                      placeholder="vless://uuid@host:443?type=ws&security=tls&sni=...&host=...&path=/..."
                    />
                  </label>
                  <div className="export-actions" style={{ alignItems: "end" }}>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() => {
                        const parsed = parseVlessUri(vlessSettings.vlessUri);
                        if (!parsed) return void toast.error("Invalid VLESS URI");
                        setVlessSettings((p) => ({
                          ...p,
                          uuid: parsed.uuid || p.uuid,
                          port: parsed.port || p.port,
                          sni: parsed.sni || p.sni,
                          host: parsed.host || p.host,
                          path: parsed.path || p.path,
                        }));
                        toast.success("Parsed VLESS URI");
                      }}
                    >
                      Parse URI
                    </button>
                    <button
                      className="btn ghost"
                      type="button"
                      onClick={() => setVlessResults([])}
                    >
                      Clear
                    </button>
                  </div>
                  <label>
                    UUID
                    <input
                      value={vlessSettings.uuid}
                      onChange={(e) =>
                        setVlessSettings((p) => ({ ...p, uuid: e.target.value }))
                      }
                      placeholder="uuid"
                    />
                  </label>
                  <label>
                    Port
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={vlessSettings.port}
                      onChange={(e) =>
                        setVlessSettings((p) => ({
                          ...p,
                          port: Math.max(1, Math.min(65535, Number(e.target.value) || 443)),
                        }))
                      }
                    />
                  </label>
                  <label>
                    SNI
                    <input
                      value={vlessSettings.sni}
                      onChange={(e) =>
                        setVlessSettings((p) => ({ ...p, sni: e.target.value }))
                      }
                      placeholder="example.com"
                    />
                  </label>
                  <label>
                    Host
                    <input
                      value={vlessSettings.host}
                      onChange={(e) =>
                        setVlessSettings((p) => ({ ...p, host: e.target.value }))
                      }
                      placeholder="example.com"
                    />
                  </label>
                  <label>
                    WS Path
                    <input
                      value={vlessSettings.path}
                      onChange={(e) =>
                        setVlessSettings((p) => ({ ...p, path: e.target.value }))
                      }
                      placeholder="/"
                    />
                  </label>
                  <label>
                    Retest Top N IPs
                    <input
                      type="number"
                      min={1}
                      max={200}
                      value={vlessSettings.topN}
                      onChange={(e) =>
                        setVlessSettings((p) => ({
                          ...p,
                          topN: Math.max(1, Math.min(200, Number(e.target.value) || 20)),
                        }))
                      }
                    />
                  </label>
                  <label>
                    Concurrency
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={vlessSettings.concurrency}
                      onChange={(e) =>
                        setVlessSettings((p) => ({
                          ...p,
                          concurrency: Math.max(1, Math.min(100, Number(e.target.value) || 20)),
                        }))
                      }
                    />
                  </label>
                </div>
                <div className="export-actions">
                  <button
                    className="btn primary"
                    type="button"
                    onClick={vlessRetest}
                    disabled={vlessIsTesting}
                  >
                    {vlessIsTesting ? "Testing..." : "Retest Last Scan IPs"}
                  </button>
                  <button
                    className="btn ghost"
                    type="button"
                    onClick={() => {
                      const ok = vlessResults.filter((r) => r.status === "success");
                      const lines = ok
                        .map((r, i) =>
                          buildVlessUri({
                            ip: r.ip,
                            port: r.port,
                            uuid: vlessSettings.uuid.trim(),
                            sni: vlessSettings.sni.trim(),
                            host: vlessSettings.host.trim(),
                            path: vlessSettings.path.trim() || "/",
                            name: `CrimsonCF-${i + 1}`,
                          }),
                        )
                        .join("\n");
                      if (!lines) return void toast.error("No OK IPs to export");
                      downloadBlob(
                        new Blob([lines], { type: "text/plain" }),
                        `crimsoncf_vless_uris_${new Date().toISOString().replace(/[:.]/g, "-")}.txt`,
                      );
                    }}
                  >
                    Export URIs (TXT)
                  </button>
                </div>
              </div>

              <div className="export-card" style={{ marginTop: 10 }}>
                <h4>Retest Results</h4>
                <p>
                  {vlessResults.filter((r) => r.status === "success").length} ok /{" "}
                  {vlessResults.length} total
                </p>
                <div className="mini-table">
                  <table>
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Latency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vlessResults.slice(0, 200).map((r) => (
                        <tr key={r.ip}>
                          <td>{r.ip}</td>
                          <td>{r.port}</td>
                          <td className={`st ${r.status}`}>{r.status}</td>
                          <td>{r.latency ?? "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </section>

        <footer className="footer">
          <p>Built by amir0zx</p>
          <a href="https://github.com/amir0zx" target="_blank" rel="noreferrer">
            github.com/amir0zx
          </a>
        </footer>
      </div>
    </div>
  );
}

export default App;
