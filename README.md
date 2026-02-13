# CrimsonCLS

**CrimsonCLS** is a fast **Cloudflare IP scanner** that tests endpoints using **Layer 4 (TCP handshake)** (not HTTPS), keeps scan history, exports clean newline TXT lists, and generates ready-to-import configs for **Xray-core**, **sing-box**, and **Clash**.

If you searched for: **cloudflare ip scanner**, **cloudflare ip range scanner**, **cloudflare tunnel ip scanner**, **warp ip scanner**, **fastest cloudflare ip**, this project is built for exactly that workflow.

## Features

- **L4 handshake probing** (TCP connect latency + open/closed)
- **Parallel scanning** (configurable concurrency)
- **IP range groups + paging**: CDN / Tunnel / WARP / Custom / All
- **Sources**: fetch ranges from URLs/APIs, presets for Cloudflare official lists
- **Results filters** + capability tags (CDN/Tunnel/WARP/BPB heuristics)
- **Exports**:
  - TXT (one IP per line, real newlines)
  - JSON/XLSX tables
  - Proxy configs: **Xray**, **sing-box**, **Clash (YAML/JSON)**
- **Cloudflare DNS tab**: push fastest IPs into A records automatically (replace mode)

## Quick Start (Docker Compose, recommended)

This runs the UI and probe server on **your own PC** so results match **your network**.

```bash
docker compose up -d
```

Open:

- `http://localhost:8080`

## Why not HTTPS probes?

Many Cloudflare IPs won’t complete HTTPS the way you expect (SNI/certs/ciphers). CrimsonCLS uses **TCP handshake tests** to reliably measure reachability/latency.

## Hosted UI vs running on user PC

Browsers block calling `http://localhost:8787` from an `https://` hosted site (mixed content). If you want **real user-PC scanning**, use the Docker Compose setup above.

## Cloudflare DNS (Fastest IPs to A records)

In the **DNS** tab you can:

- select top N fastest IPs (from last scan)
- filter by capabilities
- replace existing A records for a hostname

Use a scoped Cloudflare API token (Zone DNS Edit only for that zone).

## Development

```bash
yarn install
yarn dev
```

## Releases & Docker Images

- GitHub Container Registry image: `ghcr.io/amir0zx/crimsoncls:latest`

## Persian README

- `README.fa.md`

## License

TBD (choose MIT/Apache-2.0 if you want it fully open).

---

Built by `github.com/amir0zx`
