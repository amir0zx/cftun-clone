import { motion } from 'framer-motion';
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
} from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Toaster, toast } from 'sonner';
import * as XLSX from 'xlsx';

type ProbeState = 'success' | 'failed' | 'timeout' | 'pending';
type BatchStatus = 'running' | 'completed' | 'cancelled';
type Tab = 'scanner' | 'sources' | 'history' | 'results' | 'analytics' | 'export';

type ExportFormat = 'txt' | 'csv' | 'json' | 'xlsx';

type ExportRow = Record<string, string | number | null>;

type ProbeResponse = {
  ip: string;
  mode: 'l4_tcp_handshake';
  testedPorts: number[];
  overall: 'success' | 'failed';
  l4: Array<{ port: number; status: ProbeState; latency: number | null }>;
};

type ScanResult = {
  id: string;
  batchId: string;
  ipAddress: string;
  ipRange: string;
  overall: ProbeState;
  tcp80: ProbeState;
  tcp443: ProbeState;
  tcp2053: ProbeState;
  tcp8443: ProbeState;
  openPorts: number;
  latency: number | null;
  createdAt: string;
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
};

type LogEntry = {
  id: string;
  ts: string;
  level: 'info' | 'ok' | 'warn' | 'error';
  text: string;
};

const STORAGE_KEYS = {
  history: 'cftun_history_v2',
  results: 'cftun_results_v2',
  ranges: 'cftun_ranges_v2',
  sources: 'cftun_sources_v2',
};

const DEFAULT_RANGES = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
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
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toCsv(rows: ExportRow[]): string {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const esc = (v: unknown) => {
    const s = String(v ?? '');
    if (/[\",\\n]/.test(s)) return `\"${s.replace(/\"/g, '\"\"')}\"`;
    return s;
  };
  const lines = [headers.join(',')];
  for (const row of rows) lines.push(headers.map((h) => esc(row[h])).join(','));
  return lines.join('\\n');
}

function exportRows(format: ExportFormat, rows: ExportRow[], filenameBase: string): void {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const name = `${filenameBase}_${ts}`;

  if (format === 'json') {
    downloadBlob(new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' }), `${name}.json`);
    return;
  }

  if (format === 'csv') {
    downloadBlob(new Blob([toCsv(rows)], { type: 'text/csv' }), `${name}.csv`);
    return;
  }

  if (format === 'txt') {
    const text = rows.map((r) => Object.values(r)[0]).join('\\n');
    downloadBlob(new Blob([text], { type: 'text/plain' }), `${name}.txt`);
    return;
  }

  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'export');
  const out = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  downloadBlob(new Blob([out], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), `${name}.xlsx`);
}

function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
  );
}

function isValidCidr(v: string): boolean {
  const [ip, prefixRaw] = v.trim().split('/');
  if (!ip || !prefixRaw) return false;
  const prefix = Number(prefixRaw);
  return isValidIPv4(ip) && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32;
}

function ipToInt(ip: string): number {
  const [a, b, c, d] = ip.split('.').map(Number);
  return (((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0;
}

function intToIp(v: number): string {
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

function expandCidr(cidr: string, limit: number): string[] {
  if (!isValidCidr(cidr)) return [];
  const [ip, prefixRaw] = cidr.split('/');
  const prefix = Number(prefixRaw);
  const hostCount = 2 ** (32 - prefix);
  const count = Math.min(hostCount, Math.max(1, limit));
  const base = ipToInt(ip);
  const out: string[] = [];
  for (let i = 1; i <= count; i += 1) out.push(intToIp((base + i) >>> 0));
  return out;
}

function sampleCidr(cidr: string, limit: number, mode: 'sequential' | 'random'): string[] {
  if (mode === 'sequential') return expandCidr(cidr, limit);
  if (!isValidCidr(cidr)) return [];

  const [ip, prefixRaw] = cidr.split('/');
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
    if (typeof value === 'string') {
      const matches = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])\b/g) || [];
      matches.forEach((m) => {
        if (isValidCidr(m)) found.add(m);
      });
      return;
    }
    if (Array.isArray(value)) return value.forEach(walk);
    if (value && typeof value === 'object') Object.values(value as Record<string, unknown>).forEach(walk);
  };
  walk(payload);
  return [...found];
}

function Progress({ value }: { value: number }) {
  return (
    <div className="progress-shell">
      <motion.div className="progress-bar" animate={{ width: `${value}%` }} transition={{ duration: 0.35 }} />
    </div>
  );
}

async function probeIp(ip: string, ports: number[], signal?: AbortSignal): Promise<ProbeResponse> {
  const response = await fetch('/api/probe', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip, ports }),
    signal,
  });
  if (!response.ok) throw new Error('Probe API error');
  return (await response.json()) as ProbeResponse;
}

function App() {
  const [ranges, setRanges] = useState<string[]>(() => readStorage(STORAGE_KEYS.ranges, DEFAULT_RANGES));
  const [selectedRanges, setSelectedRanges] = useState<string[]>([]);
  const [history, setHistory] = useState<ScanBatch[]>(() => readStorage(STORAGE_KEYS.history, []));
  const [allResults, setAllResults] = useState<ScanResult[]>(() => readStorage(STORAGE_KEYS.results, []));
  const [sources, setSources] = useState<SourceItem[]>(() => readStorage(STORAGE_KEYS.sources, []));

  const [activeTab, setActiveTab] = useState<Tab>('scanner');
  const [isScanning, setIsScanning] = useState(false);
  const [currentBatch, setCurrentBatch] = useState<ScanBatch | null>(null);
  const [liveResults, setLiveResults] = useState<ScanResult[]>([]);
  const [ipsPerRange, setIpsPerRange] = useState(3);

  const [historyQuery, setHistoryQuery] = useState('');
  const [historyDate, setHistoryDate] = useState('');

  const [sourceName, setSourceName] = useState('');
  const [sourceUrl, setSourceUrl] = useState('');
  const [portToggles, setPortToggles] = useState<number[]>([80, 443, 7844, 2053, 2083, 2087, 2096, 8443]);
  const [customPort, setCustomPort] = useState('');
  const [scanWorkers, setScanWorkers] = useState(20);
  const [sampleMode, setSampleMode] = useState<'sequential' | 'random'>('random');

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [resultFilterQuery, setResultFilterQuery] = useState('');
  const [resultFilterStatus, setResultFilterStatus] = useState<'all' | 'success' | 'failed'>('all');
  const [resultFilterMinOpen, setResultFilterMinOpen] = useState(0);
  const [resultOnlyLastBatch, setResultOnlyLastBatch] = useState(true);

  const runRef = useRef(false);
  const abortersRef = useRef<AbortController[]>([]);

  function pushLog(level: LogEntry['level'], text: string): void {
    const entry: LogEntry = { id: crypto.randomUUID(), ts: new Date().toLocaleTimeString(), level, text };
    setLogs((prev) => [entry, ...prev].slice(0, 250));
  }

  function togglePort(port: number): void {
    setPortToggles((prev) => (prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port]));
  }

  function addCustomPort(): void {
    const p = Number(customPort.trim());
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      toast.error('Invalid port');
      return;
    }
    setPortToggles((prev) => (prev.includes(p) ? prev : [...prev, p]));
    setCustomPort('');
  }

  useEffect(() => writeStorage(STORAGE_KEYS.ranges, ranges), [ranges]);
  useEffect(() => writeStorage(STORAGE_KEYS.history, history), [history]);
  useEffect(() => writeStorage(STORAGE_KEYS.results, allResults), [allResults]);
  useEffect(() => writeStorage(STORAGE_KEYS.sources, sources), [sources]);

  const mergedResults = liveResults.length ? liveResults : allResults;

  const stats = useMemo(() => {
    const success = mergedResults.filter((r) => r.overall === 'success').length;
    const failed = mergedResults.filter((r) => r.overall === 'failed').length;
    const timeout = mergedResults.filter(
      (r) =>
        r.tcp80 === 'timeout' ||
        r.tcp443 === 'timeout' ||
        r.tcp2053 === 'timeout' ||
        r.tcp8443 === 'timeout'
    ).length;
    return { success, failed, timeout };
  }, [mergedResults]);

  const historyFiltered = useMemo(() => {
    const q = historyQuery.trim().toLowerCase();
    return history.filter((b) => {
      const queryOk =
        !q || b.name.toLowerCase().includes(q) || b.ipRanges.some((r) => r.toLowerCase().includes(q));
      const dateOk = !historyDate || b.createdAt.slice(0, 10) === historyDate;
      return queryOk && dateOk;
    });
  }, [history, historyDate, historyQuery]);

  const pieData = [
    { name: 'Success', value: stats.success },
    { name: 'Failed', value: stats.failed },
    { name: 'Timeout', value: stats.timeout },
  ];

  const chartData = useMemo(() => {
    const byMinute = new Map<string, number>();
    mergedResults.forEach((r) => {
      const k = r.createdAt.slice(0, 16).replace('T', ' ');
      byMinute.set(k, (byMinute.get(k) || 0) + 1);
    });
    return [...byMinute.entries()].slice(-22).map(([time, count]) => ({ time, count }));
  }, [mergedResults]);

  const filteredResults = useMemo(() => {
    const q = resultFilterQuery.trim().toLowerCase();
    let base = mergedResults;
    if (resultOnlyLastBatch && currentBatch) base = base.filter((r) => r.batchId === currentBatch.id);
    if (q) base = base.filter((r) => r.ipAddress.includes(q) || r.ipRange.toLowerCase().includes(q));
    if (resultFilterStatus !== 'all') base = base.filter((r) => r.overall === resultFilterStatus);
    base = base.filter((r) => r.openPorts >= resultFilterMinOpen);
    return [...base].sort((a, b) => (a.latency ?? 1e9) - (b.latency ?? 1e9));
  }, [currentBatch, mergedResults, resultFilterMinOpen, resultFilterQuery, resultFilterStatus, resultOnlyLastBatch]);

  const openPortsDist = useMemo(() => {
    const map = new Map<number, number>();
    for (const r of filteredResults) map.set(r.openPorts, (map.get(r.openPorts) ?? 0) + 1);
    return [...map.entries()].sort((a, b) => a[0] - b[0]).map(([openPorts, count]) => ({ openPorts, count }));
  }, [filteredResults]);

  const latencyBuckets = useMemo(() => {
    // Buckets in ms for usefulness
    const buckets = [50, 100, 200, 400, 800, 1500, 3000];
    const counts = new Map<string, number>();
    const labelFor = (ms: number | null) => {
      if (ms == null) return 'n/a';
      for (const b of buckets) if (ms <= b) return `<=${b}`;
      return `>${buckets[buckets.length - 1]}`;
    };
    for (const r of filteredResults) {
      const k = labelFor(r.latency);
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    const order = ['<=50','<=100','<=200','<=400','<=800','<=1500','<=3000',`>${buckets[buckets.length-1]}`,'n/a'];
    return order.filter((k) => counts.has(k)).map((k) => ({ bucket: k, count: counts.get(k) ?? 0 }));
  }, [filteredResults]);

  const progress =
    currentBatch && currentBatch.totalIps > 0
      ? Math.round((currentBatch.scannedCount / currentBatch.totalIps) * 100)
      : 0;

  function toggleRange(range: string): void {
    setSelectedRanges((prev) => (prev.includes(range) ? prev.filter((r) => r !== range) : [...prev, range]));
  }

  function clearLogs(): void {
    setLogs([]);
    toast.success('Logs cleared');
  }

  function clearResults(): void {
    setLiveResults([]);
    setAllResults([]);
    setCurrentBatch(null);
    toast.success('Results cleared');
    pushLog('info', 'Results cleared');
  }

  async function addSource(): Promise<void> {
    if (!sourceName.trim() || !sourceUrl.trim()) {
      toast.error('Add source name + URL');
      pushLog('warn', 'Source add rejected: missing name or URL');
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
      };
      setSources((prev) => [item, ...prev]);
      setSourceName('');
      setSourceUrl('');
      toast.success('Source added');
      pushLog('ok', `Added source "${item.name}"`);
    } catch {
      toast.error('Invalid URL');
      pushLog('error', `Source add failed: invalid URL "${sourceUrl}"`);
    }
  }

  async function fetchSource(source: SourceItem): Promise<void> {
    try {
      const response = await fetch(source.url);
      const contentType = response.headers.get('content-type') || '';
      const payload: unknown = contentType.includes('application/json') ? await response.json() : await response.text();
      const cidrs = extractCidrs(payload);

      if (!cidrs.length) {
        toast.error(`No valid CIDR ranges in ${source.name}`);
        pushLog('warn', `No CIDR ranges found from source ${source.name}`);
        return;
      }

      setRanges((prev) => [...new Set([...prev, ...cidrs])]);
      setSources((prev) =>
        prev.map((s) =>
          s.id === source.id ? { ...s, ranges: cidrs, lastFetched: new Date().toISOString() } : s
        )
      );
      toast.success(`Fetched ${cidrs.length} ranges from ${source.name}`);
      pushLog('ok', `Fetched ${cidrs.length} ranges from ${source.name}`);
    } catch {
      toast.error(`Fetch failed for ${source.name}`);
      pushLog('error', `Source fetch failed: ${source.name}`);
    }
  }

  async function startScan(): Promise<void> {
    if (!selectedRanges.length) {
      toast.error('Select at least one CIDR range');
      pushLog('warn', 'Start scan blocked: no ranges selected');
      return;
    }

    const ports = [...new Set(portToggles)].filter((p) => Number.isInteger(p) && p > 0 && p <= 65535).sort((a, b) => a - b);
    if (!ports.length) {
      toast.error('Select at least one port');
      pushLog('warn', 'Start scan blocked: no ports selected');
      return;
    }

    setIsScanning(true);
    setLiveResults([]);
    runRef.current = true;
    abortersRef.current = [];
    pushLog('info', `Starting L4 scan on ports [${ports.join(', ')}] for ${selectedRanges.length} ranges`);

    const startedAt = Date.now();
    const targets = selectedRanges.flatMap((range) =>
      sampleCidr(range, ipsPerRange, sampleMode).map((ip) => ({ ip, range }))
    );

    if (!targets.length) {
      toast.error('No testable IPs from selection');
      setIsScanning(false);
      pushLog('warn', 'No testable IPs generated from selected CIDRs');
      return;
    }

    const batchId = crypto.randomUUID();
    const baseBatch: ScanBatch = {
      id: batchId,
      name: `Scan ${new Date().toLocaleString()}`,
      createdAt: new Date().toISOString(),
      status: 'running',
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
        const probe = await probeIp(target.ip, ports, controller.signal);
        const tcp80 = probe.l4.find((t) => t.port === 80)?.status || 'failed';
        const tcp443 = probe.l4.find((t) => t.port === 443)?.status || 'failed';
        const tcp2053 = probe.l4.find((t) => t.port === 2053)?.status || 'failed';
        const tcp8443 = probe.l4.find((t) => t.port === 8443)?.status || 'failed';
        const openPorts = probe.l4.filter((p) => p.status === 'success').length;
        const latency = probe.l4.find((t) => t.status === 'success')?.latency || probe.l4[0]?.latency || null;

        const result: ScanResult = {
          id: crypto.randomUUID(),
          batchId,
          ipAddress: target.ip,
          ipRange: target.range,
          overall: probe.overall,
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
          probe.overall === 'success' ? 'ok' : 'error',
          `${target.ip} => ${probe.overall.toUpperCase()} (${openPorts}/${probe.l4.length} open ports)`
        );

        if (probe.overall === 'success') success += 1;
        else failed += 1;
      } catch (e) {
        // AbortError = user hit Stop
        failed += 1;
        const name = (e as { name?: string } | null)?.name;
        if (name === 'AbortError') {
          pushLog('warn', `${target.ip} => aborted`);
        } else {
          pushLog('error', `${target.ip} => probe failed (API/network error)`);
        }
      } finally {
        scanned += 1;
        setCurrentBatch((prev) =>
          prev ? { ...prev, scannedCount: scanned, successCount: success, failedCount: failed } : prev
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

    const finalStatus: BatchStatus = runRef.current && scanned >= targets.length ? 'completed' : 'cancelled';
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

    if (finalStatus === 'completed') {
      toast.success(`Completed: ${success} success, ${failed} failed`);
      pushLog('ok', `Scan complete: ${success} success / ${failed} failed`);
    } else {
      toast.warning('Scan cancelled');
      pushLog('warn', 'Scan cancelled by user');
    }
  }

  function stopScan(): void {
    runRef.current = false;
    abortersRef.current.forEach((c) => c.abort());
    pushLog('warn', 'Stop requested by user');
  }

  function rerun(batch: ScanBatch): void {
    setSelectedRanges(batch.ipRanges);
    setActiveTab('scanner');
    toast.info('Scan preset loaded');
    pushLog('info', `Loaded previous batch: ${batch.name}`);
  }

  const tabs: Array<{ id: Tab; label: string; icon: ReactNode }> = [
    { id: 'scanner', label: 'Scanner', icon: <Radar size={14} /> },
    { id: 'sources', label: 'Sources', icon: <Database size={14} /> },
    { id: 'history', label: 'History', icon: <RefreshCw size={14} /> },
    { id: 'results', label: 'Results', icon: <Wifi size={14} /> },
    { id: 'analytics', label: 'Analytics', icon: <Gauge size={14} /> },
    { id: 'export', label: 'Export', icon: <Download size={14} /> },
  ];

  const currentBatchResults = useMemo(() => {
    if (!currentBatch) return [];
    return mergedResults.filter((r) => r.batchId === currentBatch.id);
  }, [currentBatch, mergedResults]);

  const validIpsLastBatch = useMemo(() => {
    if (!currentBatch) return [];
    return currentBatchResults.filter((r) => r.overall === 'success').map((r) => r.ipAddress);
  }, [currentBatch, currentBatchResults]);

  const validIpsAll = useMemo(() => {
    const set = new Set<string>();
    for (const r of mergedResults) if (r.overall === 'success') set.add(r.ipAddress);
    return [...set];
  }, [mergedResults]);

  const summary = useMemo(() => {
    if (!currentBatch) return null;
    const portsOpenAvg =
      currentBatchResults.length > 0
        ? Math.round(
            currentBatchResults.reduce((acc, r) => acc + r.openPorts, 0) / currentBatchResults.length
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

  function exportValidIps(format: ExportFormat, scope: 'last' | 'all', filenameBase: string): void {
    const ips = scope === 'last' ? validIpsLastBatch : validIpsAll;
    const rows: ExportRow[] = ips.map((ip) => ({ ip }));
    exportRows(format, rows, filenameBase);
  }

  function exportResultsTable(format: ExportFormat, rows: ScanResult[], filenameBase: string): void {
    const tableRows: ExportRow[] = rows.map((r) => ({
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

  return (
    <div className="ui-root">
      <Toaster theme="dark" richColors position="top-right" />

      <div className="bg-glow g1" />
      <div className="bg-glow g2" />
      <div className="grid-overlay" />

      <div className="page-wrap">
        <motion.header className="hero" initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }}>
          <div>
            <p className="eyebrow">CrimsonCLS</p>
            <h1>
              <span>CRIMSON</span> CLS SCANNER
            </h1>
            <p className="sub">L4 TCP handshake probing with persistent history, sources and live charts.</p>
          </div>

          <div className="hero-actions">
            <button className="btn ghost" onClick={() => setRanges(DEFAULT_RANGES)} type="button">
              <Cloud size={15} /> Reset Cloudflare
            </button>
            {isScanning ? (
              <button className="btn danger" onClick={stopScan} type="button">
                <Square size={14} /> Stop
              </button>
            ) : (
              <button className="btn primary" onClick={startScan} type="button" disabled={!selectedRanges.length}>
                <Play size={14} /> Start Scan
              </button>
            )}
          </div>
        </motion.header>

        <section className="stats-grid">
          {[
            { label: 'Total Ranges', value: ranges.length, icon: <Database size={16} /> },
            { label: 'Selected', value: selectedRanges.length, icon: <Shield size={16} /> },
            {
              label: 'Success Rate',
              value:
                mergedResults.length > 0
                  ? `${Math.round((stats.success / mergedResults.length) * 100)}%`
                  : '0%',
              icon: <Activity size={16} />,
            },
            { label: 'Results', value: mergedResults.length, icon: <Wifi size={16} /> },
          ].map((s, index) => (
            <motion.article key={s.label} className="stat-card" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.05 }}>
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
                  setIpsPerRange(Math.max(1, Math.min(50, Number(e.target.value) || 1)))
                }
              />
            </label>
            <div className="meta">Estimated IPs: {selectedRanges.length * ipsPerRange}</div>
            <div className="meta">L4 mode: TCP handshake only (connect test)</div>
            <label>
              Workers
              <input
                type="number"
                min={1}
                max={100}
                value={scanWorkers}
                onChange={(e) => setScanWorkers(Math.max(1, Math.min(100, Number(e.target.value) || 1)))}
              />
            </label>
            <label>
              Sampling
              <select value={sampleMode} onChange={(e) => setSampleMode(e.target.value as 'sequential' | 'random')}>
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
                  className={`port-chip ${portToggles.includes(p) ? 'on' : ''}`}
                  onClick={() => togglePort(p)}
                >
                  {p}
                </button>
              ))}
              {portToggles
                .filter((p) => ![80, 443, 7844, 2053, 2083, 2087, 2096, 8443].includes(p))
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
              <button className="btn ghost" type="button" onClick={addCustomPort}>
                Add
              </button>
            </div>
          </div>

          {(currentBatch || isScanning) && (
            <div className="progress-block">
              <div className="progress-head">
                <strong>{currentBatch?.name || 'Scanning...'}</strong>
                <span>{currentBatch?.scannedCount || 0}/{currentBatch?.totalIps || 0}</span>
              </div>
              <Progress value={progress} />
            </div>
          )}

          {summary && !isScanning && (
            <div className="summary-card">
              <div className="summary-head">
                <strong>Last Scan Summary</strong>
                <span className={`badge ${summary.status}`}>{summary.status}</span>
              </div>
              <div className="summary-grid">
                <div><span>Total</span><b>{summary.total}</b></div>
                <div><span>Scanned</span><b>{summary.scanned}</b></div>
                <div><span>Success</span><b>{summary.success}</b></div>
                <div><span>Failed</span><b>{summary.failed}</b></div>
                <div><span>Avg Open Ports</span><b>{summary.portsOpenAvg}</b></div>
                <div><span>Duration</span><b>{summary.durationMs ? `${Math.round(summary.durationMs / 1000)}s` : '-'}</b></div>
              </div>
              <div className="summary-actions">
                <button className="btn ghost" type="button" onClick={clearResults}>Clear Results</button>
                <button className="btn ghost" type="button" onClick={clearLogs}>Clear Logs</button>
                <button className="btn ghost" type="button" onClick={() => exportValidIps('txt', 'last', 'crimsoncls_valid_ips_last')}>Export Valid (TXT)</button>
                <button className="btn ghost" type="button" onClick={() => exportValidIps('xlsx', 'last', 'crimsoncls_valid_ips_last')}>Export Valid (XLSX)</button>
              </div>
            </div>
          )}

          <div className="tabs-row">
            {tabs.map((t) => (
              <button key={t.id} className={`tab ${activeTab === t.id ? 'active' : ''}`} onClick={() => setActiveTab(t.id)} type="button">
                {t.icon}
                {t.label}
              </button>
            ))}
          </div>

          {activeTab === 'scanner' && (
            <div className="panel-block">
              <div className="row-tools">
                <button className="btn ghost" onClick={() => setSelectedRanges(selectedRanges.length === ranges.length ? [] : [...ranges])} type="button">{selectedRanges.length === ranges.length ? 'Unselect All' : 'Select All'}</button>
                <button className="btn ghost" onClick={() => setSelectedRanges([])} type="button">Clear</button>
                <button className="btn ghost" onClick={clearResults} type="button">Clear Results</button>
              </div>
              <div className="cidr-grid">
                {ranges.map((r) => (
                  <button key={r} className={`cidr-chip ${selectedRanges.includes(r) ? 'on' : ''}`} onClick={() => toggleRange(r)} type="button">{r}</button>
                ))}
              </div>

              <section className="terminal-card">
                <div className="terminal-head">
                  <span className="dot red" />
                  <span className="dot yellow" />
                  <span className="dot green" />
                  <strong>Live Probe Log</strong>
                  <div className="terminal-actions">
                    <button className="btn ghost" type="button" onClick={clearLogs}>Clear</button>
                  </div>
                </div>
                <div className="terminal-body">
                  {logs.length === 0 && <p className="terminal-empty">No logs yet. Start a scan to stream events.</p>}
                  {logs.map((log) => (
                    <p key={log.id} className={`terminal-line ${log.level}`}>
                      <span>[{log.ts}]</span> {log.text}
                    </p>
                  ))}
                </div>
              </section>
            </div>
          )}

          {activeTab === 'sources' && (
            <div className="panel-block">
              <div className="source-form">
                <input placeholder="Source name" value={sourceName} onChange={(e) => setSourceName(e.target.value)} />
                <input placeholder="https://example.com/list.txt or api endpoint" value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} />
                <button className="btn primary" onClick={addSource} type="button">Add</button>
              </div>

              <div className="source-list">
                {!sources.length && <p className="empty">No custom sources yet.</p>}
                {sources.map((s) => (
                  <article key={s.id} className="source-item">
                    <div>
                      <h4>{s.name}</h4>
                      <p>{s.url}</p>
                      <small>{s.lastFetched ? `Last fetched: ${new Date(s.lastFetched).toLocaleString()}` : 'Never fetched'}</small>
                    </div>
                    <div className="source-actions">
                      <button className="btn ghost" onClick={() => fetchSource(s)} type="button">Fetch</button>
                      <button className="btn danger" onClick={() => setSources((prev) => prev.filter((x) => x.id !== s.id))} type="button">Remove</button>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'history' && (
            <div className="panel-block">
              <div className="search-row">
                <div className="search-wrap">
                  <Search size={14} />
                  <input placeholder="Search by name or range" value={historyQuery} onChange={(e) => setHistoryQuery(e.target.value)} />
                </div>
                <input type="date" value={historyDate} onChange={(e) => setHistoryDate(e.target.value)} />
              </div>

              <div className="history-list">
                {!historyFiltered.length && <p className="empty">No scan history</p>}
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
                    <Progress value={h.totalIps ? Math.round((h.successCount / h.totalIps) * 100) : 0} />
                    <div className="line3">
                      <small>{h.ipRanges.slice(0, 3).join(' · ')}</small>
                      <div className="history-actions">
                        <button className="btn ghost" onClick={() => rerun(h)} type="button">Re-run</button>
                        <button
                          className="btn ghost"
                          onClick={() => {
                            const batchResults = mergedResults.filter((r) => r.batchId === h.id && r.overall === 'success');
                            exportRows('txt', batchResults.map((r) => ({ ip: r.ipAddress })), `crimsoncls_valid_ips_${h.id}`);
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

          {activeTab === 'results' && (
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
                  <select value={resultFilterStatus} onChange={(e) => setResultFilterStatus(e.target.value as any)}>
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
                    onChange={(e) => setResultFilterMinOpen(Math.max(0, Number(e.target.value) || 0))}
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
                <button
                  className="btn ghost"
                  type="button"
                  onClick={() => exportResultsTable('xlsx', filteredResults, 'crimsoncls_results_table')}
                >
                  Export Table (XLSX)
                </button>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
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
                    {filteredResults.slice(0, 500).map((r) => (
                      <tr key={r.id}>
                        <td>{r.ipAddress}</td>
                        <td>{r.ipRange}</td>
                        <td className={`st ${r.overall}`}>{r.overall}</td>
                        <td className={`st ${r.tcp80}`}>{r.tcp80}</td>
                        <td className={`st ${r.tcp443}`}>{r.tcp443}</td>
                        <td className={`st ${r.tcp2053}`}>{r.tcp2053}</td>
                        <td className={`st ${r.tcp8443}`}>{r.tcp8443}</td>
                        <td>{r.openPorts}</td>
                        <td>{r.latency ?? '-'}</td>
                        <td>{new Date(r.createdAt).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'analytics' && (
            <div className="analytics-grid">
              <article className="chart-card">
                <h4>Probe Flow</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="redFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff4a4a" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#ff4a4a" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" hide />
                      <YAxis stroke="#9a5b5b" />
                      <Tooltip contentStyle={{ background: '#130707', border: '1px solid #4d1a1a', color: '#ffd9d9' }} />
                      <Area dataKey="count" type="monotone" stroke="#ff5454" fill="url(#redFill)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Result Distribution</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={90} label>
                        {pieData.map((entry, i) => <Cell key={entry.name} fill={['#ff4f4f', '#5d0000', '#ffb366'][i % 3]} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: '#130707', border: '1px solid #4d1a1a', color: '#ffd9d9' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </article>
              <article className="chart-card">
                <h4>Latency Buckets (Filtered)</h4>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={latencyBuckets}>
                      <XAxis dataKey="bucket" stroke="#9a5b5b" />
                      <YAxis stroke="#9a5b5b" />
                      <Tooltip contentStyle={{ background: '#130707', border: '1px solid #4d1a1a', color: '#ffd9d9' }} />
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
                      <Tooltip contentStyle={{ background: '#130707', border: '1px solid #4d1a1a', color: '#ffd9d9' }} />
                      <Bar dataKey="count" fill="#ffb366" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </article>
            </div>
          )}

          {activeTab === 'export' && (
            <div className="panel-block">
              <h3 className="export-title">Export Center</h3>
              <div className="export-grid">
                <article className="export-card">
                  <h4>Valid IPs (Last Scan)</h4>
                  <p>{validIpsLastBatch.length} IPs</p>
                  <div className="export-actions">
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('txt', 'last', 'crimsoncls_valid_ips_last')}>TXT</button>
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('csv', 'last', 'crimsoncls_valid_ips_last')}>CSV</button>
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('json', 'last', 'crimsoncls_valid_ips_last')}>JSON</button>
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('xlsx', 'last', 'crimsoncls_valid_ips_last')}>XLSX</button>
                  </div>
                </article>

                <article className="export-card">
                  <h4>Valid IPs (All)</h4>
                  <p>{validIpsAll.length} unique IPs</p>
                  <div className="export-actions">
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('txt', 'all', 'crimsoncls_valid_ips_all')}>TXT</button>
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('csv', 'all', 'crimsoncls_valid_ips_all')}>CSV</button>
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('json', 'all', 'crimsoncls_valid_ips_all')}>JSON</button>
                    <button className="btn ghost" type="button" onClick={() => exportValidIps('xlsx', 'all', 'crimsoncls_valid_ips_all')}>XLSX</button>
                  </div>
                </article>

                <article className="export-card">
                  <h4>Results Table (Filtered)</h4>
                  <p>{filteredResults.length} rows (sorted by latency)</p>
                  <div className="export-actions">
                    <button className="btn ghost" type="button" onClick={() => exportResultsTable('csv', filteredResults, 'crimsoncls_results_table_filtered')}>CSV</button>
                    <button className="btn ghost" type="button" onClick={() => exportResultsTable('json', filteredResults, 'crimsoncls_results_table_filtered')}>JSON</button>
                    <button className="btn ghost" type="button" onClick={() => exportResultsTable('xlsx', filteredResults, 'crimsoncls_results_table_filtered')}>XLSX</button>
                  </div>
                </article>
              </div>
            </div>
          )}
        </section>

        <footer className="footer">
          <p>Built by amir0zx</p>
          <a href="https://github.com/amir0zx" target="_blank" rel="noreferrer">github.com/amir0zx</a>
        </footer>
      </div>
    </div>
  );
}

export default App;
