import requests
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils import load_list_from_file, generate_case_variations, parse_headers, parse_cookies
from urllib.parse import urlparse, urlunparse
from requests.structures import CaseInsensitiveDict
from src.print_utils import print_status, log_error, print_ordered_results

parent_dir = pathlib.Path(__file__).parent.parent

def load_fuzz_data():
    """
    Loads fuzz data from files.
    """
    fuzz_paths = load_list_from_file(parent_dir / "data" / "fuzz_paths.txt")
    appended_fuzz_paths = load_list_from_file(parent_dir / "data" / "appended_fuzz_paths.txt")
    params = load_list_from_file(parent_dir / "data" / "params.txt")
    default_headers = load_list_from_file(parent_dir / "data" / "default_headers.txt")
    return fuzz_paths, appended_fuzz_paths, params, default_headers

def test_url(url, method, min_length, exclude_lengths, headers, body, cookie, verbose, proxy=None, insecure=False, output_file=None):
    """
    Executes a single HTTP request with the given parameters and prints the result.
    Also returns the response length.
    """
    try:
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        cookies = parse_cookies(cookie)
        
        response = requests.request(
            method,
            url,
            headers=headers,
            data=body,
            cookies=cookies,
            proxies=proxies,
            verify=not insecure # Ignore SSL verification if the "insecure" flag is enabled. "Verify" is equal to False if "insecure" is true, otherwise it is equal to True.
        )
        response_length = len(response.content)
        return print_status(method, str(response.status_code), url, min_length, exclude_lengths, headers, cookies, body, verbose, response_length, output_file)
    except requests.RequestException as e:
        error_message = log_error(method, url, e, output_file)
        if verbose and error_message:
            print(error_message)
        return 0

def generate_fuzzed_urls(target_url, fuzz_paths, appended_fuzz_paths, all, level):
    """
    Generates a set of fuzzed URLs based on the target URL and fuzz paths.
    """
    urls_to_test = set()
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    path_parts = parsed_url.path.split('/')

    for fuzz in fuzz_paths:
        for i in range(1, len(path_parts) + 1):
            fuzzed_url = f"{base_url}{'/'.join(path_parts[1:i])}/{fuzz}/{'/'.join(path_parts[i:])}"
            urls_to_test.add(fuzzed_url)
            urls_to_test.add(fuzzed_url.rstrip('/') if fuzzed_url.endswith('/') else fuzzed_url + '/')

    for fuzz in appended_fuzz_paths:
        urls_to_test.add(target_url + fuzz)
        urls_to_test.add((target_url.rstrip('/') if target_url.endswith('/') else target_url) + fuzz)

    if parsed_url.scheme == 'https':
        urls_to_test.add(urlunparse(('http', parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)))
    elif parsed_url.scheme == 'http':
        urls_to_test.add(urlunparse(('https', parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)))

    for i in range(len(path_parts)):
        temp_path = path_parts[:]
        temp_path[i] = temp_path[i].upper()
        uppercase_url = f"{base_url}/{'/'.join(temp_path)}"
        urls_to_test.add(uppercase_url)
        urls_to_test.add(uppercase_url.rstrip('/') if uppercase_url.endswith('/') else uppercase_url + '/')

    if all or level > 2:
        for i in range(len(path_parts)):
            temp_path = path_parts[:]
            for variation in generate_case_variations(path_parts[i]):
                temp_path[i] = variation
                case_variation_url = f"{base_url}{'/'.join(temp_path)}"
                urls_to_test.add(case_variation_url)
                urls_to_test.add(case_variation_url.rstrip('/') if case_variation_url.endswith('/') else case_variation_url + '/')

    return urls_to_test

def forbidden_bypass(target_url, headers, body, cookie, methods, verbose, min_length, exclude_length, num_threads, proxy, insecure, level, all, output_file=None):
    """
    Performs fuzz testing across various HTTP methods, headers, and URL fuzzing using multithreading.
    """
    exclude_lengths = [int(x) for x in exclude_length.split(",")] if exclude_length else []
    fuzz_paths, appended_fuzz_paths, params, default_headers = load_fuzz_data()

    success_count = 0
    urls_to_test = generate_fuzzed_urls(target_url, fuzz_paths, appended_fuzz_paths, all, level)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        if all or level > 1:
            for method in methods:
                for header in default_headers:
                    header_parts = header.split(':', 1)
                    if len(header_parts) == 2:
                        headers_dict = parse_headers(headers) if headers else CaseInsensitiveDict()
                        headers_dict[header_parts[0].strip()] = header_parts[1].strip()
                        futures.append(executor.submit(test_url, target_url, method, min_length, exclude_lengths, headers_dict, body, cookie, verbose, proxy, insecure, output_file))
                        futures.append(executor.submit(test_url, target_url.rstrip('/') if target_url.endswith('/') else target_url + '/', method, min_length, exclude_lengths, headers_dict, body, cookie, verbose, proxy, insecure, output_file))

        for url in urls_to_test:
            for method in methods:
                futures.append(executor.submit(test_url, url, method, min_length, exclude_lengths, parse_headers(headers), body, cookie, verbose, proxy, insecure, output_file))

        for param in params:
            for method in methods:
                futures.append(executor.submit(test_url, target_url + "?" + param, method, min_length, exclude_lengths, parse_headers(headers), body, cookie, verbose, proxy, insecure, output_file))
                futures.append(executor.submit(test_url, target_url.rstrip('/') if target_url.endswith('/') else target_url + '/' + "?" + param, method, min_length, exclude_lengths, parse_headers(headers), body, cookie, verbose, proxy, insecure, output_file))

        for future in as_completed(futures):
            success_count += future.result()

    return success_count