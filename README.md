# FBps (Forbidden Bypass)

![FBps banner](/img/fbps.png)

FBps (Forbidden Bypass) is a fast and efficient fuzzing script designed for bypassing HTTP status codes 403 and 401. This tool enables security researchers and penetration testers to identify potential vulnerabilities in web applications through extensive HTTP method testing and request manipulation.

> Use this tool only on systems you own or are explicitly authorized to test.

## Features

- **Flexible HTTP Method Testing**: specify one or more HTTP methods, including custom methods, to evaluate server responses.
- **Level-based Testing**: use `-L` to choose how aggressive and exhaustive the fuzzing should be.
- **URL Fuzzing**: automatically generate variations of the target URL to uncover hidden endpoints or methods.
- **Query Parameter Fuzzing**: automatically append parameters from a wordlist to the target URL to trigger alternative code paths.
- **Header Manipulation**: easily add custom headers to your requests, including default headers for common bypass techniques.
- **Body and Cookie Support**: customize your requests with a specified body and cookies to simulate different user sessions and scenarios.
- **Uppercase and Case-Variation Tests**: test for path case sensitivity (e.g., `/path` vs `/PATH` and other mixed-case variants).
- **Off-by-slash**: test variations in URL paths by adding or removing trailing slashes.
- **Multithreading**: use multiple threads with `-t` to speed up testing and increase throughput.
- **Proxy Support**: route requests through HTTP or SOCKS proxies (e.g. Burp, ZAP, VPN gateways).
- **Global Rate Limiting**: limit the total number of requests per second with `-rl` to avoid overwhelming the target or triggering rate limits.
- **Response Filtering**: reduce noise using `--min-length` and `--exclude-length` to ignore uninteresting responses.
- **Verbose Mode and JSON Output**: enable detailed per-request logs with `-v` and export structured results to a JSON file with `-o`.

## Installation

1. Ensure you have Python 3 installed on your system.
2. Install the required dependencies using the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python fbps.py [-h] [-m METHOD] [-H HEADER] [-b BODY] [-c COOKIES]
               [-A] [-L LEVEL] [-v] [-o OUTPUT.json] [-t THREADS]
               [-rl RATE_LIMIT] [-p PROXY]
               [--min-length MIN_LENGTH] [--exclude-length L1,L2,...]
               [--insecure]
               url
```

## Options

- `url`  
  Target URL to test. If the scheme is omitted, `https://` is automatically prepended.

- `-m, --method`  
  HTTP method or comma-separated list of methods (e.g., `GET,POST,HEAD`).  
  The default method is `GET`.

- `-L, --level`  
  Level of tests to perform (1–3, default: 1). Each level includes all tests from the previous levels:
    - Level 1: URL fuzzing, query parameter fuzzing, protocol switching, uppercase path tests.
    - Level 2: headers fuzzing and additional mixed-case URL variations.
    - Level 3: extended off-by-slash testing across generated URLs and headers.

- `-A, --all`  
  Perform ALL tests with a set of common HTTP methods.

- `-H, --header`  
  Specify headers in `Key: Value` format (can be used multiple times).

- `-b, --body`  
  Specify the request body.

- `-c, --cookies`  
  Specify cookies in `key=value` format, separated by semicolons (e.g. `session=abc123; isAdmin=true`).

- `-t, --threads`  
  Number of worker threads (default: 5).

- `-rl, --rate-limit`  
  Maximum number of requests per second, globally across all threads.  
  If not set, rate limiting is disabled.

- `-p, --proxy`  
  Use an HTTP or SOCKS proxy (e.g. `http://127.0.0.1:8080` or `socks5h://user:pass@host:port`).

- `--min-length`  
  Ignore responses whose body length is less than the specified value.

- `--exclude-length`  
  Comma-separated list of exact response lengths to ignore (e.g. `0,35,125`).

- `--insecure`  
  Skip SSL certificate verification and suppress warnings.

- `-v, --verbose`  
  Enable detailed per-request output.

- `-o, --output`  
  Save results to a JSON file (e.g. `results.json`).

## Examples

1. Basic GET scan

```bash
python fbps.py https://example.com/secret
```

2. Increase the test level

```bash
python fbps.py -L 3 https://example.com/secret
```

3. Scan with multiple HTTP methods

```bash
python fbps.py -m GET,POST,PUT https://example.com/secret
```

4. Perform all tests with all common HTTP methods

```bash
python fbps.py -A https://example.com/secret
```

5. Using custom headers, cookies and body

```bash
python fbps.py -H "User-Agent: FBps" -c "test=1; foo=2" -b "user=user&pwd=pass" https://example.com/secret
```

6. Specify number of threads

```bash
python fbps.py -t 20 https://example.com/secret
```

7. Route traffic through a proxy (SOCKS or HTTP)

```bash
python fbps.py -p http://127.0.0.1:8080 https://example.com/secret
python fbps.py -p socks5h://user:pass@host:port https://example.com/secret
```

8. Enable verbose output and save results to JSON

```bash
python fbps.py -v -o results.json https://example.com
```

## Notes

- **Fuzzing Data Files**: the tool loads fuzzing data (paths, headers, parameters) from the text files shipped with the project (e.g. `fuzz_paths.txt`, `appended_fuzz_paths.txt`, `params.txt`, `default_headers.txt`). Make sure these files are present in the `data/` directory when running the script.
- **Responsible Use**: this tool is intended for security research and academic purposes. Always obtain permission before testing a target.
