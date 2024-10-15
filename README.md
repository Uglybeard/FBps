# FBps (Forbidden Bypass)

![FBps banner](/img/fbps.png)

FBps (Forbidden Bypass) is a fast and efficient fuzzing script designed for bypassing HTTP status codes 403 and 401. This tool enables security researchers and penetration testers to identify potential vulnerabilities in web applications through extensive HTTP method testing and request manipulation.

## Features

- **Flexible HTTP Method Testing**: Specify one or more HTTP methods, including custom methods, to evaluate server responses.
- **Header Manipulation**: Easily add custom headers to your requests, including default headers for common bypass techniques.
- **Body and Cookie Support**: Customize your requests with a specified body and cookies to simulate different user sessions.
- **URL Fuzzing**: Automatically generate variations of the target URL to uncover hidden endpoints or methods.
- **Uppercase Tests**: Test for case sensitivity in paths (e.g., /path vs /PaTh).
- **Multithreading**: Leverage multiple threads to speed up testing and increase the efficiency of your requests.
- **Proxy Support**: Route requests through SOCKS proxies for anonymity and to bypass network restrictions.
- **Verbose Mode**: Enable detailed output for in-depth analysis of each request and response.

## Installation

To install FBps, first ensure you have Python 3 installed on your machine. Then, install the required dependencies using the requirements.txt file.

```bash
pip install -r requirements.txt
```

## Usage

fbps.py [-h] [-m METHOD] [-H HEADER] [-b BODY] [-c COOKIES] [-A] [-L LEVEL] [-v] [-o OUTPUT] [-t THREADS] [-p PROXY] [--min-length MIN_LENGTH] [--insecure] url


## Options

- `-m, --method` Specify one or more HTTP methods, separated by commas (e.g., GET,POST,HEAD). The default method is GET.
- `-H, --header` Specify headers in `Key: Value` format (can be used multiple times).
- `-b, --body` Specify the request body.
- `-c, --cookies` Specify cookies in `Key = Value` format. Multiple cookies should be separated by a semicolon (;).
- `-A, --all` Perform all tests with common HTTP methods.
- `-L, --level`: Specify the level of tests to perform, from 1 to 3 (default: 1). Each level includes all tests from the previous levels:
    - Level 1: URL fuzzing, protocol switching.
    - Level 2: Headers fuzzing.
    - Level 3: Uppercase URL variations.
- `-v, --verbose` Enable verbose output.
- `-o, --output` Specify an output file to save the results.
- `-t, --threads` Specify number of threads (default: 5).
- `-p, --proxy` Specify SOCKS proxy (format: socks5h://user:pass@host:port).
- `--min-length` Skip responses with a length less than the specified value.
- `--insecure` Skip SSL certificate verification and suppress warnings.
- `-h, --help` Display this help message.

## Examples

1. Basic usage

```bash
python fbps.py https://example.com
```
2. Specify HTTP methods and level

```bash
python fbps.py -m GET,POST https://example.com -L 3
```

3. Perform all tests with all common HTTP methods

```bash
python fbps.py -A https://example.com
```

4. Using custom Headers, Cookies and Body

```bash
python fbps.py -H "User-Agent: fuzzing-tool" -c "test=1; foo=2" -b "user=user&password=pass" -m GET https://example.com
```

5. Specify number of threads (default=5)

```bash
python fbps.py -t 40 https://example.com
```

6. Using a Proxy

```bash
python fbps.py -p socks5h://user:pass@host:port https://example.com
```

7. Enable Verbose Output and Save Results

```bash
python fbps.py -v -o results.txt https://example.com
```

## Notes

- **Multithreading**: Adjust the `-t` (threads) parameter according to the speed of the target server. Higher thread counts may speed up testing but could lead to throttling or blocking by the server.
- **Fuzzing Paths**: The tool loads fuzzing paths from `data/fuzz_paths.txt`, `data/appended_fuzz_paths.txt`, and query parameters from `data/params.txt`. Ensure these files are in the same directory as the script for extended fuzzing.