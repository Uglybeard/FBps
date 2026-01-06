import time
import threading
import socket
import ssl
import requests
import pathlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED, CancelledError
from urllib.parse import urlparse, urlunparse

from requests.structures import CaseInsensitiveDict

from src.utils import load_list_from_file, generate_case_variations, parse_headers, parse_cookies, load_raw_bytes_from_file
from src.print_utils import print_status, log_error, print_ordered_results

parent_dir = pathlib.Path(__file__).parent.parent


def parse_exclude_lengths(exclude_length):
    """
    Parse the exclude_length parameter into a list of integers.

    Returns an empty list if exclude_length is omitted or contains invalid values.
    """
    if not exclude_length:
        return []

    try:
        return [int(x.strip()) for x in exclude_length.split(",") if x.strip()]
    except ValueError:
        print(f"[!] Invalid exclude-length format: {exclude_length}")
        return []


def load_fuzz_data():
    """
    Load fuzzing data from files under the data/ directory.

    Returns:
        fuzz_paths, appended_fuzz_paths, params, default_headers
    """
    fuzz_paths = load_list_from_file(parent_dir / "data" / "fuzz_paths.txt")
    appended_fuzz_paths = load_list_from_file(parent_dir / "data" / "appended_fuzz_paths.txt")
    params = load_list_from_file(parent_dir / "data" / "params.txt")
    default_headers = load_list_from_file(parent_dir / "data" / "default_headers.txt")
    return fuzz_paths, appended_fuzz_paths, params, default_headers

def load_raw_bytes():
    """
    Load raw byte values from the raw_bytes.txt file.

    Returns a list of single-byte bytes objects.
    """
    try:
        return load_raw_bytes_from_file(parent_dir / "data" / "raw_bytes.txt")
    except FileNotFoundError:
        return []

class RateLimiter:
    """
    Simple thread-safe rate limiter based on a minimum interval between requests.
    """

    def __init__(self, rate_per_sec):
        """
        Initialize the rate limiter with a maximum number of requests per second.

        If rate_per_sec is None or less than or equal to zero, no rate limiting is applied.
        """
        self.rate_per_sec = rate_per_sec
        self.lock = threading.Lock()
        self.last_request_ts = 0.0
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0

    def wait_for_slot(self):
        """
        Block the caller until the next request slot is available.
        """
        if not self.rate_per_sec or self.min_interval <= 0:
            return

        with self.lock:
            now = time.time()
            elapsed = now - self.last_request_ts

            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
                now = time.time()

            self.last_request_ts = now
            


def _flip_trailing_slash(url):
    """
    Toggle the trailing slash in the given URL.

    If the URL ends with '/', remove it; otherwise, append '/'.
    """
    return url.rstrip("/") if url.endswith("/") else url + "/"


def test_url(url, method, min_length, exclude_lengths, headers, body, cookie, verbose,
             proxy=None, insecure=False, output_file=None, rate_limiter=None):
    """
    Execute a single HTTP request with the given parameters and print the result.

    Returns the success value as determined by print_status.
    """
    try:
        if rate_limiter is not None:
            rate_limiter.wait_for_slot()  # Optional global rate limiting across all threads

        proxies = {"http": proxy, "https": proxy} if proxy else None
        cookies = parse_cookies(cookie)

        response = requests.request(
            method,
            url,
            headers=headers,
            data=body,
            cookies=cookies,
            proxies=proxies,
            verify=not insecure,  # Ignore SSL verification if "insecure" is True.
            timeout=15
        )

        response_length = len(response.content)

        return print_status(
            method,
            str(response.status_code),
            url,
            min_length,
            exclude_lengths,
            headers,
            cookies,
            body,
            verbose,
            response_length,
            output_file
        )

    except KeyboardInterrupt:
        raise  # Propagate interrupt to main thread
    except requests.RequestException as e:
        error_message = log_error(method, url, e, output_file)
        if verbose and error_message:
            print(error_message)
        return 0


def test_raw_request_target(parsed_url, method, raw_target, display_url, min_length, exclude_lengths, headers, body, cookie,
    verbose, proxy=None, insecure=False, output_file=None, rate_limiter=None):
    """
    Send a single HTTP request using a raw request-target (with arbitrary bytes).

    Supports HTTP and HTTPS proxies via CONNECT method.
    """
    # Global rate limiting
    if rate_limiter is not None:
        rate_limiter.wait_for_slot()

    host = parsed_url.hostname
    if not host:
        error_msg = "Invalid host in URL for raw trim test"
        log_error(method, display_url, error_msg, output_file)
        if verbose:
            print(error_msg)
        return 0

    port = parsed_url.port
    if not port:
        port = 443 if parsed_url.scheme == "https" else 80

    cookies = parse_cookies(cookie)
    body_bytes = body.encode("utf-8") if body else b""

    # Determine connection target (proxy or direct)
    if proxy:
        # Parse proxy URL
        proxy_url = urlparse(proxy if "://" in proxy else f"http://{proxy}")
        connect_host = proxy_url.hostname
        connect_port = proxy_url.port or 8080
        use_proxy = True
    else:
        connect_host = host
        connect_port = port
        use_proxy = False

    sock = None
    try:
        # Direct TCP connection (to proxy or origin)
        sock = socket.create_connection((connect_host, connect_port), timeout=15)
        sock.settimeout(15)

        # Handle HTTPS through proxy using CONNECT
        if use_proxy and parsed_url.scheme == "https":
            # Send CONNECT request to establish tunnel
            connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\n"
            connect_request += f"Host: {host}:{port}\r\n\r\n"
            sock.sendall(connect_request.encode("ascii"))

            # Read CONNECT response
            connect_response = b""
            while b"\r\n\r\n" not in connect_response:
                chunk = sock.recv(4096)
                if not chunk:
                    raise socket.error("Proxy closed connection during CONNECT")
                connect_response += chunk

            # Verify CONNECT success
            status_line = connect_response.split(b"\r\n")[0]
            if b"200" not in status_line:
                raise socket.error(f"Proxy CONNECT failed: {status_line.decode('ascii', errors='ignore')}")

        # Optional TLS wrapping (after CONNECT for proxy, directly for non-proxy HTTPS)
        if parsed_url.scheme == "https":
            context = ssl.create_default_context()
            if insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        # Build request line with raw_target bytes
        request_parts = []

        # For HTTP through proxy, use absolute URI; otherwise use raw_target as-is
        if use_proxy and parsed_url.scheme == "http":
            absolute_target = f"{parsed_url.scheme}://{parsed_url.netloc}".encode("ascii") + raw_target
            request_parts.append(method.encode("ascii") + b" ")
            request_parts.append(absolute_target)
            request_parts.append(b" HTTP/1.1\r\n")
        else:
            request_parts.append(method.encode("ascii") + b" ")
            request_parts.append(raw_target)
            request_parts.append(b" HTTP/1.1\r\n")

        # Host header
        request_parts.append(f"Host: {parsed_url.netloc}\r\n".encode("ascii"))

        # Custom headers
        if headers:
            for k, v in headers.items():
                try:
                    header_line = f"{k}: {v}\r\n".encode("latin-1")
                    request_parts.append(header_line)
                except UnicodeEncodeError:
                    if verbose:
                        print(f"[!] Warning: Could not encode header {k}: {v}")

        # Cookie header
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            try:
                request_parts.append(f"Cookie: {cookie_str}\r\n".encode("latin-1"))
            except UnicodeEncodeError:
                if verbose:
                    print("[!] Warning: Could not encode cookies")

        # Body / Content-Length
        if body_bytes:
            request_parts.append(
                f"Content-Length: {len(body_bytes)}\r\n".encode("ascii")
            )

        # Close connection after response
        request_parts.append(b"Connection: close\r\n\r\n")

        # Append body
        request = b"".join(request_parts) + body_bytes

        # Send request
        sock.sendall(request)

        # Read response
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

        raw_response = b"".join(chunks)
        if not raw_response:
            error_msg = "Empty response in raw trim test"
            log_error(method, display_url, error_msg, output_file)
            if verbose:
                print(error_msg)
            return 0

        # Parse status line
        first_line, _, rest = raw_response.partition(b"\r\n")
        try:
            parts = first_line.split(b" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 else 0
        except (ValueError, IndexError):
            status_code = 0

        # Find the body (after headers)
        headers_end = raw_response.find(b"\r\n\r\n")
        if headers_end != -1:
            body_data = raw_response[headers_end + 4:]
            response_length = len(body_data)
        else:
            response_length = 0

        return print_status(
            method,
            str(status_code),
            display_url,
            min_length,
            exclude_lengths,
            headers,
            cookies,
            body,
            verbose,
            response_length,
            output_file,
        )

    except KeyboardInterrupt:
        raise  # Propagate interrupt to main thread
    except socket.timeout:
        error_message = "Raw trim test error: Connection timeout"
        if verbose:
            print(error_message)
        log_error(method, display_url, error_message, output_file)
        return 0
    except (socket.error, ssl.SSLError) as e:
        error_message = f"Raw trim test error: {e}"
        if verbose:
            print(error_message)
        log_error(method, display_url, error_message, output_file)
        return 0
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def generate_version_downgrade_urls(parsed_url, base_url_without_slash, all, level):
    """
    Generate additional URLs by downgrading API version segments like /api/v3/users -> /api/v2/users, /api/v1/users.
    """
    urls = set()
    path_parts = parsed_url.path.split("/")

    for idx, segment in enumerate(path_parts):
        match = re.fullmatch(r"[vV](\d+)", segment)
        if not match:
            continue

        current_version = int(match.group(1))
        if current_version <= 1:
            continue

        for new_version in range(current_version - 1, 0, -1):
            new_parts = path_parts[:]
            new_parts[idx] = f"v{new_version}"
            new_path = "/".join(new_parts)
            downgraded_url = f"{base_url_without_slash}{new_path}"
            urls.add(downgraded_url)

            # Trailing Slash variants (Level 3 and above)
            if all or level > 2:
                urls.add(_flip_trailing_slash(downgraded_url))

    return urls


def generate_fuzzed_urls(target_url, fuzz_paths, appended_fuzz_paths, all, level):
    """
    Generate a set of fuzzed URLs based on the target URL and fuzz paths.

    Returns a set of unique fuzzed URLs.
    """
    urls_to_test = set()
    parsed_url = urlparse(target_url)

    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    base_url_without_slash = f"{parsed_url.scheme}://{parsed_url.netloc}"
    path_parts = parsed_url.path.split("/")

    # Path-based URL fuzzing (Level 1 and above)
    for fuzz in fuzz_paths:
        for i in range(1, len(path_parts) + 1):
            if i == 1:
                fuzzed_url = f"{base_url}{'/'.join(path_parts[1:i])}{fuzz}/{'/'.join(path_parts[i:])}"
            else:
                fuzzed_url = f"{base_url}{'/'.join(path_parts[1:i])}/{fuzz}/{'/'.join(path_parts[i:])}"

            urls_to_test.add(fuzzed_url)

            # Trailing Slash variants (Level 3 and above)
            if all or level > 2:
                urls_to_test.add(_flip_trailing_slash(fuzzed_url))

    # Appended path fuzzing (Level 1 and above)
    normalized_target = target_url.rstrip("/")  # Ensure no trailing slash at the end, to append fuzz directly (e.g., /target -> /targetFUZZ)

    for fuzz in appended_fuzz_paths:
        appended_url = normalized_target + fuzz
        urls_to_test.add(appended_url)

        # Trailing Slash variants (Level 3 and above)
        if all or level > 2:
            urls_to_test.add(_flip_trailing_slash(appended_url))

    # Protocol switching (Level 1 and above)
    if parsed_url.scheme == "https":
        urls_to_test.add(
            urlunparse(
                (
                    "http",
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    parsed_url.query,
                    parsed_url.fragment
                )
            )
        )
    elif parsed_url.scheme == "http":
        urls_to_test.add(
            urlunparse(
                (
                    "https",
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    parsed_url.query,
                    parsed_url.fragment
                )
            )
        )

    # Uppercase path segment variants (Level 1 and above)
    for i in range(len(path_parts)):
        temp_path = path_parts[:]
        temp_path[i] = temp_path[i].upper()

        # Remove empty segments to avoid double slashes
        clean_segments = [p for p in temp_path if p]
        path = "/".join(clean_segments)

        uppercase_url = f"{base_url_without_slash}/{path}" if path else base_url_without_slash
        urls_to_test.add(uppercase_url)

        # Trailing Slash variants (Level 3 and above)
        if all or level > 2:
            urls_to_test.add(_flip_trailing_slash(uppercase_url))

    # Mixed-case path segment variants (Level 2 and above)
    if all or level > 1:
        for i in range(len(path_parts)):
            for variation in generate_case_variations(path_parts[i]):
                temp_path = path_parts[:]
                temp_path[i] = variation
                case_variation_url = f"{base_url_without_slash}{'/'.join(temp_path)}"
                urls_to_test.add(case_variation_url)

                # Trailing Slash variants (Level 3 and above)
                if all or level > 2:
                    urls_to_test.add(_flip_trailing_slash(case_variation_url))
    
    # Version downgrade variants (Level 1 and above)
    urls_to_test.update(
        generate_version_downgrade_urls(parsed_url, base_url_without_slash, all, level)
    )

    return urls_to_test


def generate_trim_raw_targets(parsed_url, raw_bytes, all, level):
    """
    Build raw request-target variants to test trim inconsistencies.

    Returns a list of tuples: (display_url, raw_request_target_bytes)
    """
    raw_targets = []

    # Example: /trim/ -> base "/trim"
    base_path = parsed_url.path.rstrip("/")
    if not base_path:
        base_path = "/"

    for b in raw_bytes:
        # Variant without trailing slash: /trim\xNN
        target_no_slash = base_path.encode("ascii") + b
        display_no_slash = (
            f"{parsed_url.scheme}://{parsed_url.netloc}"
            f"{base_path}\\x{b[0]:02x}"
        )
        raw_targets.append((display_no_slash, target_no_slash))

        # Trailing Slash variants (Level 3 and above) (e.g., /trim/\xNN)
        if all or level > 2:
            target_with_slash = (base_path + "/").encode("ascii") + b
            display_with_slash = (
                f"{parsed_url.scheme}://{parsed_url.netloc}"
                f"{base_path}/\\x{b[0]:02x}"
            )
            raw_targets.append((display_with_slash, target_with_slash))

    return raw_targets


def forbidden_bypass(target_url, headers, body, cookie, methods, verbose, min_length,
                     exclude_length, num_threads, proxy, insecure, level, all,
                     rate_limit=None, output_file=None, user_agent=None):
    """
    Perform HTTP fuzzing across methods, headers, and URL variants using multithreading and optional rate limiting.

    Returns the total number of successful bypasses found.
    """
    exclude_lengths = parse_exclude_lengths(exclude_length)
    fuzz_paths, appended_fuzz_paths, params, default_headers = load_fuzz_data()

    # Load optional raw bytes for trim inconsistency tests
    raw_bytes = load_raw_bytes()

    base_headers = parse_headers(headers) if headers else CaseInsensitiveDict()

    # Set custom User-Agent if provided
    if user_agent and "User-Agent" not in base_headers:
        base_headers["User-Agent"] = user_agent


    success_count = 0
    urls_to_test = generate_fuzzed_urls(target_url, fuzz_paths, appended_fuzz_paths, all, level)
    parsed_url = urlparse(target_url)

    # Global rate limiter shared by all worker threads
    if rate_limit and rate_limit > 0:
        rate_limiter = RateLimiter(rate_limit)
    else:
        rate_limiter = None

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []

        # Basic Trailing Slash Inconsistencies test, performed only if the Trailing Slash Inconsistencies test is excluded (Level < 3)
        if not all and level < 3:
            base_url_for_methods = _flip_trailing_slash(target_url)
            for method in methods:
                futures.append(
                    executor.submit(
                        test_url,
                        base_url_for_methods,
                        method,
                        min_length,
                        exclude_lengths,
                        base_headers.copy(),
                        body,
                        cookie,
                        verbose,
                        proxy,
                        insecure,
                        output_file,
                        rate_limiter
                    )
                )

        # Headers manipulation (Level 2 and above)
        if all or level > 1:
            for method in methods:
                for header in default_headers:
                    header_parts = header.split(":", 1)
                    if len(header_parts) == 2:
                        headers_dict = base_headers.copy()
                        headers_dict[header_parts[0].strip()] = header_parts[1].strip()

                        futures.append(
                            executor.submit(
                                test_url,
                                target_url,
                                method,
                                min_length,
                                exclude_lengths,
                                headers_dict,
                                body,
                                cookie,
                                verbose,
                                proxy,
                                insecure,
                                output_file,
                                rate_limiter
                            )
                        )

                        # Trailing Slash variants (Level 3 and above)
                        if all or level > 2:
                            toggled_target = _flip_trailing_slash(target_url)
                            futures.append(
                                executor.submit(
                                    test_url,
                                    toggled_target,
                                    method,
                                    min_length,
                                    exclude_lengths,
                                    headers_dict.copy(),
                                    body,
                                    cookie,
                                    verbose,
                                    proxy,
                                    insecure,
                                    output_file,
                                    rate_limiter
                                )
                            )

        # Trim inconsistencies using raw request-target bytes (Level 2 and above)
        if raw_bytes and (all or level > 1):
            trim_targets = generate_trim_raw_targets(parsed_url, raw_bytes, all, level)
            for display_url, raw_target in trim_targets:
                for method in methods:
                    futures.append(
                        executor.submit(
                            test_raw_request_target,
                            parsed_url,
                            method,
                            raw_target,
                            display_url,
                            min_length,
                            exclude_lengths,
                            base_headers.copy(),
                            body,
                            cookie,
                            verbose,
                            proxy,
                            insecure,
                            output_file,
                            rate_limiter,
                        )
                    )

        # URL Fuzzing performed using URLs generated in the generate_fuzzed_urls function (Level 1 and above)
        for url in urls_to_test:
            for method in methods:
                futures.append(
                    executor.submit(
                        test_url,
                        url,
                        method,
                        min_length,
                        exclude_lengths,
                        base_headers.copy(),
                        body,
                        cookie,
                        verbose,
                        proxy,
                        insecure,
                        output_file,
                        rate_limiter
                    )
                )

        # Query parameter fuzzing (Level 1 and above)
        for param in params:
            url_with_param = f"{target_url}?{param}"
            flipped_url_with_param = f"{_flip_trailing_slash(target_url)}?{param}"

            for method in methods:
                futures.append(
                    executor.submit(
                        test_url,
                        url_with_param,
                        method,
                        min_length,
                        exclude_lengths,
                        base_headers.copy(),
                        body,
                        cookie,
                        verbose,
                        proxy,
                        insecure,
                        output_file,
                        rate_limiter
                    )
                )

                # Trailing Slash variants (Level 3 and above)
                if all or level > 2:
                    futures.append(
                        executor.submit(
                            test_url,
                            flipped_url_with_param,
                            method,
                            min_length,
                            exclude_lengths,
                            base_headers.copy(),
                            body,
                            cookie,
                            verbose,
                            proxy,
                            insecure,
                            output_file,
                            rate_limiter
                        )
                    )

        # Handle completion of futures with interrupt support
        try:
            for future in as_completed(futures):
                try:
                    success_count += future.result()
                except KeyboardInterrupt:
                    # Cancel all remaining futures
                    for f in futures:
                        f.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
        except KeyboardInterrupt:
            print("\n[!] Cancelling pending requests...")
            raise

    return success_count