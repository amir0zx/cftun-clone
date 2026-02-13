import cors from 'cors';
import express from 'express';
import net from 'node:net';
const app = express();
const PORT = Number(process.env.PROBE_PORT || 8787);

app.use(
  cors({
    origin: true,
    credentials: false,
  })
);
app.use(express.json());

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
  const defaultPorts = [80, 443, 2053, 2083, 2087, 2096, 8443];
  if (!Array.isArray(input)) return defaultPorts;
  const ports = input
    .map((p) => Number(p))
    .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535);
  return ports.length ? [...new Set(ports)] : defaultPorts;
}

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

app.listen(PORT, () => {
  console.log(`[probe-server] listening on http://localhost:${PORT}`);
});
