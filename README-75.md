# Shodan API Tool

A thin wrapper around the [Shodan](https://shodan.io) REST API for
recon: look up everything Shodan has indexed about a specific IP
(open ports, service banners, known CVEs, org/location), or run a
search query across Shodan's entire index.

## Requirements
```
pip install requests
```

You need a Shodan API key — free tier available at
https://account.shodan.io/register (check Shodan's own pricing page
for current query-credit limits, since these change over time).

**Set your key via environment variable (recommended, keeps it out of
shell history):**
```bash
export SHODAN_API_KEY="your_key_here"
```
Or pass it per-command with `--api-key`.

## Usage
```bash
# Everything Shodan knows about a specific IP
python shodan_tool.py host 1.2.3.4

# Include raw banner snippets
python shodan_tool.py host 1.2.3.4 --show-banners

# Search Shodan's index
python shodan_tool.py search "apache country:IN"
python shodan_tool.py search "product:MySQL port:3306" --limit 20
```

## What `host` shows
IP, organization, ISP, country/city, all open ports, hostnames, any
known CVEs Shodan has associated with the host, and a per-port
service banner summary (product + version, with `--show-banners` for
the raw banner text).

## What `search` shows
Total match count across all of Shodan, plus a table of the top N
results (IP, port, product, org, country) for the requested query —
see [Shodan's search query syntax](https://www.shodan.io/search/filters)
for filters like `product:`, `port:`, `country:`, `org:`, etc.

## Notes
- Some endpoints (notably `search`) may require a higher-tier API key
  depending on your Shodan plan — a `403` from the API usually means
  your key doesn't have access to that endpoint, not that something's
  broken in this script.
- `429` means you're out of query credits for the current period.

## Status
Part of a personal 100-tool security scripting project. Live API
calls couldn't be tested end-to-end in this sandbox (no internet
access, and a real API key would be needed regardless). Both the
`host` and `search` response-parsing logic were verified against
mocked responses matching Shodan's own documented API schema, along
with 401/error-handling behavior. Run it once with a real key before
relying on it in case Shodan has changed any field names since.

## License
MIT
