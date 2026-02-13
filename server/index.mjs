import cors from 'cors';
import express from 'express';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
const app = express();
const PORT = Number(process.env.PORT || process.env.PROBE_PORT || 8787);
const SERVE_STATIC = String(process.env.SERVE_STATIC || '').toLowerCase() === '1';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(
  cors({
    origin: true,
    credentials: false,
  })
);
app.use(express.json());

async function cfFetch(token, url, init = {}) {
  const res = await fetch(url, {
    ...init,
    headers: {
      ...(init.headers || {}),
      Authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
  });
  const json = await res.json().catch(() => null);
  if (!res.ok || !json || json.success === false) {
    const msg =
      (json && (json.errors?.[0]?.message || json.messages?.[0]?.message)) ||
      (json && json.error) ||
      `Cloudflare API error (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.cf = json;
    throw err;
  }
  return json;
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function tcpProbe(host, port, timeoutMs = 1800) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = new net.Socket();
    let done = false;

    const finish = (status) => {
      if (done) return;
      done = true;
      socket.destroy();
      const latency = Date.now() - started;
      resolve({ status, latency: Number.isFinite(latency) ? latency : null });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('success'));
    socket.once('timeout', () => finish('timeout'));
    socket.once('error', () => finish('failed'));

    socket.connect(port, host);
  });
}

function normalizePorts(input) {
  // Include 7844 (Cloudflare Tunnel), plus common HTTPS alt ports
  const defaultPorts = [80, 443, 7844, 2053, 2083, 2087, 2096, 8443];
  if (!Array.isArray(input)) return defaultPorts;
  const ports = input
    .map((p) => Number(p))
    .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535);
  return ports.length ? [...new Set(ports)] : defaultPorts;
}

app.get('/health', (_req, res) => {
  res.status(200).send('ok');
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'probe-server', ts: new Date().toISOString() });
});

app.post('/api/probe', async (req, res) => {
  const ip = String(req.body?.ip || '').trim();
  const ports = normalizePorts(req.body?.ports);
  if (!isValidIPv4(ip)) {
    return res.status(400).json({ error: 'Invalid IPv4 address' });
  }

  const l4 = await Promise.all(
    ports.map(async (port) => ({
      port,
      ...(await tcpProbe(ip, port, 2000)),
    }))
  );

  const anySuccess = l4.some((r) => r.status === 'success');

  return res.json({
    ip,
    mode: 'l4_tcp_handshake',
    testedPorts: ports,
    overall: anySuccess ? 'success' : 'failed',
    l4,
  });
});

app.post('/api/cf/dns/replace-a', async (req, res) => {
  const token = String(req.body?.token || '').trim();
  const zoneId = String(req.body?.zoneId || '').trim();
  const name = String(req.body?.name || '').trim();
  const proxied = Boolean(req.body?.proxied);
  const ttl = Number(req.body?.ttl || 1);
  const ips = Array.isArray(req.body?.ips) ? req.body.ips.map((x) => String(x).trim()) : [];

  if (!token) return res.status(400).json({ error: 'Missing token' });
  if (!zoneId) return res.status(400).json({ error: 'Missing zoneId' });
  if (!name || !name.includes('.')) return res.status(400).json({ error: 'Invalid record name' });

  const cleaned = ips.filter((ip) => isValidIPv4(ip));
  if (cleaned.length === 0) return res.status(400).json({ error: 'No valid IPv4 addresses' });
  if (cleaned.length > 50) return res.status(400).json({ error: 'Too many IPs (max 50)' });

  try {
    // List existing A records for this name and delete them (replace mode).
    const listUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=A&name=${encodeURIComponent(
      name,
    )}&per_page=100`;
    const listed = await cfFetch(token, listUrl, { method: 'GET' });
    const existing = Array.isArray(listed.result) ? listed.result : [];

    const deleted = [];
    for (const rec of existing) {
      if (!rec?.id) continue;
      const delUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${rec.id}`;
      await cfFetch(token, delUrl, { method: 'DELETE' });
      deleted.push(rec.id);
    }

    const created = [];
    for (const ip of cleaned) {
      const payload = {
        type: 'A',
        name,
        content: ip,
        ttl: Number.isFinite(ttl) && ttl >= 1 ? ttl : 1,
        proxied,
        comment: `CrimsonCLS auto (${new Date().toISOString()})`,
      };
      const createUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
      const out = await cfFetch(token, createUrl, { method: 'POST', body: JSON.stringify(payload) });
      created.push({ id: out.result?.id, ip });
    }

    res.json({
      ok: true,
      replaced: {
        name,
        zoneId,
        proxied,
        ttl,
        deletedCount: deleted.length,
        createdCount: created.length,
      },
      created,
    });
  } catch (e) {
    res.status(500).json({
      error: e?.message || 'Cloudflare API failed',
      requestId: crypto.randomUUID(),
    });
  }
});

if (SERVE_STATIC) {
  const distDir = path.resolve(__dirname, '..', 'dist');
  app.use(express.static(distDir, { index: false }));

  // SPA fallback: everything else becomes index.html
  // Express 5 + path-to-regexp v6 doesn't accept '*' routes; use regex.
  app.get(/.*/, (_req, res) => {
    res.sendFile(path.join(distDir, 'index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`[probe-server] listening on http://localhost:${PORT}`);
});
