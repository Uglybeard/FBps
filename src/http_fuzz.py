import time
import threading
import requests
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

from requests.structures import CaseInsensitiveDict

from src.utils import load_list_from_file, generate_case_variations, parse_headers, parse_cookies
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


def test_url(url, method, min_length, exclude_lengths, headers, body, cookie, verbose, proxy=None, insecure=False, output_file=None, rate_limiter=None):
    """
    Execute a single HTTP request with the given parameters and print the result.

    Returns the success value as determined by print_status.
    """
    try:
        if rate_limiter is not None: 
            rate_limiter.wait_for_slot() # Optional global rate limiting across all threads

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

    except requests.RequestException as e:
        error_message = log_error(method, url, e, output_file)
        if verbose and error_message:
            print(error_message)
        return 0


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

            # Off-by-slash variants (Level 3 and above)
            if all or level > 2:
                urls_to_test.add(_flip_trailing_slash(fuzzed_url))

    # Appended path fuzzing (Level 1 and above)
    normalized_target = target_url.rstrip("/") if target_url.endswith("/") else target_url

    for fuzz in appended_fuzz_paths:
        urls_to_test.add(target_url + fuzz)

        # Off-by-slash variants (Level 3 and above)
        if all or level > 2:
            urls_to_test.add(normalized_target + fuzz)

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
        uppercase_url = f"{base_url}/{'/'.join(temp_path)}"
        urls_to_test.add(uppercase_url)

        # Off-by-slash variants (Level 3 and above)
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

                # Off-by-slash variants (Level 3 and above)
                if all or level > 2:
                    urls_to_test.add(_flip_trailing_slash(case_variation_url))

    return urls_to_test


def forbidden_bypass(target_url, headers, body, cookie, methods, verbose, min_length, exclude_length, num_threads, proxy, insecure, level, all, rate_limit=None, output_file=None):
    """
    Perform HTTP fuzzing across methods, headers, and URL variants using multithreading and optional rate limiting.

    Returns the total number of successful bypasses found.
    """
    exclude_lengths = parse_exclude_lengths(exclude_length)
    fuzz_paths, appended_fuzz_paths, params, default_headers = load_fuzz_data()

    base_headers = parse_headers(headers) if headers else CaseInsensitiveDict()

    success_count = 0
    urls_to_test = generate_fuzzed_urls(target_url, fuzz_paths, appended_fuzz_paths, all, level)

    # Global rate limiter shared by all worker threads
    if rate_limit and rate_limit > 0:
        rate_limiter = RateLimiter(rate_limit)
    else:
        rate_limiter = None

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []

        # Basic Off-by-slash test, performed only if the Off-by-slash test is excluded (Level < 3)
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

                        # Off-by-slash variants (Level 3 and above)
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

        # URL Fuzzing performed using URLS generated in the generate_fuzzed_urls function (Level 1 and above)
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
            for method in methods:
                futures.append(
                    executor.submit(
                        test_url,
                        f"{target_url}?{param}",
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
                
                # Off-by-slash variants (Level 3 and above)
                if all or level > 2:
                    futures.append(
                        executor.submit(
                            test_url,
                            target_url.rstrip("/")
                            if target_url.endswith("/")
                            else target_url + "/" + "?" + param,
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

        for future in as_completed(futures):
            success_count += future.result()

    return success_count
