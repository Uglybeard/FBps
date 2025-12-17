# FBps (Forbidden Bypass)

![FBps banner](/img/fbps.png)

FBps (Forbidden Bypass) is a fast fuzzing script focused on access-control testing (HTTP 401/403) by generating request variations across methods, URLs and headers to highlight misconfigurations, normalization inconsistencies and unexpected routing behaviors.

> Use this tool only on systems you own or are explicitly authorized to test.

## Key features

- Level-based scanning (`-L`) to control how exhaustive the test set is
- URL fuzzing (in-path payloads + appended payloads)
- Trim inconsistency checks via raw request-target bytes (optional wordlist)
- HTTP method testing (`-m` or `-A`)
- Header manipulation (default header wordlist + custom headers)
- Custom User-Agent support (`-ua`)
- API version downgrade variants (e.g. `/api/v3/...` → `/api/v2/...` → `/api/v1/...`)
- Query parameter fuzzing (wordlist-driven)
- Proxy support, multithreading, global rate limiting
- Response filtering and optional JSON reporting

## Test levels (what runs where)

Each level includes everything from the previous one.

**Level 1**
- URL fuzzing using payloads in `data/fuzz_paths.txt`
- URL suffix/appended fuzzing using `data/appended_fuzz_paths.txt`
- Query parameter fuzzing using `data/params.txt`
- Protocol switching test (http ↔ https) on the original target URL
- Uppercase path segment variants
- API version downgrade variants (e.g. `v3 → v2 → v1` when a `/vN` segment is present)
- Basic trailing-slash toggle on the original target URL

**Level 2**
- Mixed-case path segment variations
- Header fuzzing using `data/default_headers.txt`
- Trim inconsistencies via raw requests using `data/raw_bytes.txt`

**Level 3**
- Off-by-slash variants extended across generated URLs, header fuzzing, query params and trim raw targets

## Installation

1. Ensure you have Python 3 installed.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python fbps.py [-h] [-m METHOD] [-H HEADER] [-b BODY] [-c COOKIES] [-ua USER_AGENT]
               [-A] [-L LEVEL] [-v] [-o OUTPUT.json] [-t THREADS]
               [-rl RATE_LIMIT] [-p PROXY]
               [--min-length MIN_LENGTH] [--exclude-length L1,L2,...]
               [--insecure]
               url
```

## Options

- Target & scope:
  - `url` target URL
  - `-L, --level` test level (1–3)
  - `-A, --all` perform all tests with common HTTP methods (loaded from `data/methods.txt`)

- Request shaping:
  - `-m, --method` comma-separated HTTP methods (default: `GET`)
  - `-H, --header` add custom headers (`Key: Value`, repeatable)
  - `-ua, --user-agent` set a custom User-Agent header
  - `-c, --cookies` cookies string (`k=v; k2=v2`)
  - `-b, --body` request body data

- Performance & transport:
  - `-t, --threads` worker threads (default: 5)
  - `-rl, --rate-limit` max requests/sec (global across threads)
  - `-p, --proxy` HTTP/SOCKS proxy
  - `--insecure` skip TLS verification

- Noise reduction & output:
  - `--min-length` ignore responses shorter than N bytes
  - `--exclude-length` ignore exact response sizes (comma-separated)
  - `-v, --verbose` per-request output
  - `-o, --output` export results to JSON

## Examples

1) Basic scan (default method, Level 1)

```bash
python fbps.py https://example.com/secret
```

2) Increase coverage

```bash
python fbps.py -L 3 https://example.com/secret
```

4) Run all tests using the common methods list

```bash
python fbps.py -A https://example.com/secret
```

5) Explicit methods + custom User-Agent + JSON output

```bash
python fbps.py -m GET,POST,HEAD -ua "FBps/1.0" -o results.json https://example.com/secret
```

6) Proxy + global rate limit

```bash
python fbps.py -p http://127.0.0.1:8080 -rl 5 -L 2 https://example.com/secret
```

7) Increase the number of threads

```bash
python fbps.py -t 20 -A https://example.com/secret
```

## Notes

- **Wordlists / payload sources**: FBps loads fuzzing data from `data/` (e.g. `fuzz_paths.txt`, `appended_fuzz_paths.txt`, `params.txt`, `default_headers.txt`). Tune coverage by editing these files.
- **Common methods list (`-A`)**: methods are loaded from `data/methods.txt` so you can customize the set without changing code.
- **Trim inconsistencies (optional)**: level 2+ also tests raw request-target byte suffixes to detect normalization discrepancies. When using a proxy (e.g., Burp/ZAP), keep in mind that “raw” request-target bytes may be normalized or rewritten by the proxy chain, which can reduce the effectiveness of trim inconsistency checks.
- **Responsible use**: run only with explicit authorization and prefer a controlled lab environment when tuning payloads and levels.
