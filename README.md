# quic-prober

A command-line tool that simulates GFW-style active probing against QUIC proxy servers.

Send structured probe packets to a target server and a reference real QUIC server, compare their responses, and surface behavioral differences that could make the target detectable.

```
quic-prober ──── probes ────→ Target   (Hysteria2 / TUIC / etc.)
             ──── probes ────→ Reference (cloudflare.com)
             ←─── compare & report ───────────────────────
```

> [中文文档](README.zh.md)

## Probes

| Probe | What it tests |
|-------|---------------|
| `http3` | Full HTTP/3 GET — status code, headers, response time |
| `tls` | TLS handshake only — ALPN, cipher suite, certificate chain, ECH |
| `replay` | Replayed QUIC Initial packet — replay protection |
| `null` | QUIC handshake with no streams — idle behavior and close codes |
| `random` | Random UDP at 11 packet sizes (1–1500 bytes) — junk rejection |
| `malformed` | 5 malformed QUIC Initials — error handling consistency |

## Install

```bash
go install github.com/HaizakiKu/quic-prober@latest
```

Or build from source:

```bash
git clone https://github.com/HaizakiKu/quic-prober
cd quic-prober
go build -o quic-prober .
```

**Requires:** Go 1.24+

## Usage

```bash
# Basic scan
quic-prober --target your-server.com:443

# Multiple reference servers, majority-vote consensus
quic-prober --target your-server.com:443 \
            --reference cloudflare.com:443,google.com:443 \
            --reference-mode majority

# Run specific probes only
quic-prober --target your-server.com:443 --probes http3,tls

# JSON output
quic-prober --target your-server.com:443 --json | jq .

# Show raw per-reference results
quic-prober --target your-server.com:443 --verbose
```

### Flags

```
--target           host:port   Target server (required)
--reference        host:port   Comma-separated reference servers (default: cloudflare.com:443)
--reference-mode   string      How to merge multiple references (default: any)
                                 any      normal if ANY reference shows it
                                 majority normal if >50% of references show it
                                 all      normal only if ALL references show it
--probes           string      Comma-separated probe list (default: all)
                                 http3, tls, replay, null, random, malformed
--random-sizes     string      Packet sizes for random probe
                               (default: 1,8,16,32,64,128,256,512,1024,1400,1500)
--timeout          int         Per-probe timeout in seconds (default: 10)
--probe-interval   int         Milliseconds between probes (default: 2000)
--verbose          bool        Print raw result for each reference server
--json             bool        Output results as JSON to stdout
```

Before probes run, the target is checked for reachability via a quick QUIC
handshake. The run is aborted early if DNS fails or the host does not respond
within `--timeout` seconds.

## Example Output

```
quic-prober v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:    your-server.com:443
Reference: cloudflare.com:443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[✅ PASS] TLS Handshake
  ALPN h3 ✓, cipher 0x1301 ✓, cert: CN=your-server.com

[⚠️  WARN] HTTP/3 GET /
  Status 200 OK ✓
  Missing "Server" header → configure masquerade reverse proxy to add Server header

[✅ PASS] Replay probe
  Both servers: no-response ✓

[✅ PASS] Null connection
  No unprompted streams, idle timeout matches reference ✓

[✅ PASS] Random UDP (11 sizes, 1–1500 bytes)
  No response to random UDP ✓

[✅ PASS] Malformed QUIC Initial (5 variants)
  All malformed variants: no application data returned ✓

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Overall: ⚠️  LOW-MEDIUM RISK
  5 passed, 1 warning(s).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All probes passed |
| `1` | One or more warnings |
| `2` | One or more failures |

## How Scoring Works

Each probe compares the target's behavior against the merged reference result.

- **FAIL** — Target behaves in a way a real QUIC server would not. Detectable by GFW active probing.
- **WARN** — Target differs from reference in a suspicious way. May warrant attention.
- **PASS** — Target is indistinguishable from a real QUIC server on this probe.

Common failure causes and fixes:

| Probe | Failure | Fix |
|-------|---------|-----|
| `http3` | Status not 200 | Configure masquerade web server |
| `http3` | Missing `Server` header | Add header in reverse proxy config |
| `tls` | ALPN not `h3` | Enable QUIC/HTTP3 on the server |
| `tls` | Self-signed certificate | Use a CA-signed certificate |
| `replay` | Accepts replayed Initial | Ensure QUIC replay protection is active |
| `null` | Pushes stream unprompted | Disable unsolicited server push |
| `random` | Responds to random UDP | Check firewall / QUIC implementation |

## Tech Stack

- **QUIC / HTTP3** — [`quic-go`](https://github.com/quic-go/quic-go)
- **TLS** — `crypto/tls` stdlib
- **Raw UDP** — `net` stdlib
- **QUIC Initial packet** — built from scratch per RFC 9001 (AES-128-GCM + header protection)

## Disclaimer

This tool is for **authorized testing only**. Only use it against servers you own or have explicit permission to test. Some malformed-packet probes may trigger unexpected behavior in unpatched server implementations. The authors are not responsible for any damage caused by unauthorized or improper use.
