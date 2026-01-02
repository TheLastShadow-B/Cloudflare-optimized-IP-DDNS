# Project Context

## Purpose
HE.net DNS A Record Auto-Update Tool - Automatically finds optimal Cloudflare-optimized IP addresses and updates DNS records on dns.he.net. The tool fetches candidate domains from vps789.com, resolves IPs via multiple DNS servers, performs ping and speed tests, then updates the DNS A record with the best-performing IP.

## Tech Stack
- Python 3 (single-file script)
- `requests` - HTTP client for API calls
- `dnspython` (optional) - DNS resolution; falls back to `nslookup` if unavailable
- CloudflareSpeedTest (cfst) - External tool for download speed testing (auto-downloaded from GitHub)
- Standard library: `subprocess`, `socket`, `concurrent.futures`, `dataclasses`, `logging`

## Project Conventions

### Code Style
- Chinese comments and log messages (user-facing)
- English code and variable names
- Dataclasses for structured data (`Config`, `PingResult`, `SpeedTestResult`, `DomainInfo`)
- Type hints used throughout
- Configuration via `.env` file (auto-generated template if missing)

### Architecture Patterns
- Single-file CLI application (`he_dns_updater.py`)
- Configuration loaded from `.env` file in script directory
- Concurrent ping testing via `ThreadPoolExecutor`
- Graceful fallbacks (dnspython → nslookup, speed test → ping results)
- Cross-platform support (Windows, Linux, macOS)

### Testing Strategy
- Manual testing via running the script
- Debug mode available via `DEBUG=true` in `.env`

### Git Workflow
- Single main branch (no git repo initialized yet)

## Domain Context
- **HE.net (Hurricane Electric)**: Free DNS hosting service with dynamic DNS API
- **Cloudflare-optimized IPs**: IP addresses that provide better connectivity to Cloudflare CDN from certain networks (e.g., China)
- **vps789.com API**: Public API providing top-performing Cloudflare IP domains with latency/packet loss statistics
- **CloudflareSpeedTest (cfst)**: Open-source tool by XIU2 for testing Cloudflare IP download speeds

## Important Constraints
- Requires HE.net account with dynamic DNS configured
- Speed test requires a custom URL (CFST_URL) - typically a self-hosted file on Cloudflare CDN
- Network connectivity required to external APIs and DNS servers
- Platform-specific ping command parsing (Windows vs Unix)

## External Dependencies
- **vps789.com API**: `https://vps789.com/public/sum/cfIpTop20` - Source of candidate domains
- **HE.net Dynamic DNS**: `https://dyn.dns.he.net/nic/update` - DNS update endpoint
- **CloudflareSpeedTest releases**: GitHub releases for auto-downloading cfst tool
- **DNS Servers**: Configurable, defaults to 119.29.29.29 (DNSPod) and 223.5.5.5 (AliDNS)
