import requests
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils import load_list_from_file, generate_case_variations, parse_headers, parse_cookies
from urllib.parse import urlparse, urlunparse
from requests.structures import CaseInsensitiveDict

parent_dir = pathlib.Path(__file__).parent.parent
positive_results = []
output_results = []

def print_status(method, status, url, min_length, exclude_length, headers="", cookies="", body="", verbose=False, response_length=0, output_file=None):
    """
    Prints the HTTP request result, using different colors for success (2xx) and failure.
    Also prints the length of the response.
    """
    method_column_width = 7
    url_column_width = 90
    response_len_column_width = 6

    if status.startswith("2"):
        status_color="\033[0;32m"
    elif status.startswith("3"):
        status_color="\033[93m"
    else: status_color="\033[0;31m"

    colored_line = (
        f"[+] {method:<{method_column_width}} | {status_color}{status}\033[0m | Length: {response_length:<{response_len_column_width}} | "
        f"{url:<{url_column_width}} | Headers: {headers}"
    )

    plain_line = (
        f"[+] {method:<{method_column_width}} | {status} | Length: {response_length:<{response_len_column_width}} | "
        f"{url:<{url_column_width}} | Headers: {headers}\n"
    )

    if verbose:
        print(colored_line)
    
    if output_file:
        with open(output_file,"a") as f:
            f.write(plain_line)

    # If response length is less than minimum length, skip the result
    if min_length and response_length<min_length:
        return 0
    
    if exclude_length and response_length==exclude_length:
        return 0
    
    if status.startswith("2"):  # Store positive results (console output)
        positive_results.append(
            f"\n{'-' * 60}\n[+] Method:     {method:<{method_column_width}}\n"
            f"    URL:        {url}\n"
            f"    Headers:    {headers}\n"
            f"    Cookies:    {cookies}\n"
            f"    Body:       {body}\n"
            f"    Status:     {status_color}{status}\033[0m\n"
            f"    Length:     {response_length}"
        )
        if output_file: # Store positive results (file output)
            output_results.append(
            f"\n{'-' * 60}\n[+] Method:     {method:<{method_column_width}}\n"
            f"    URL:        {url}\n"
            f"    Headers:    {headers}\n"
            f"    Cookies:    {cookies}\n"
            f"    Body:       {body}\n"
            f"    Status:     {status}\n"
            f"    Length:     {response_length}"
        )
        return 1
    return 0

def print_ordered_results(output_file=None):
    """
    Organizes and prints the positive results of the HTTP requests, grouped by HTTP method.
    Each method's results are printed in an ordered manner for better readability.
    If an output file is provided, the results are also written to the file.
    """
    
    # Write the results to the console
    method_results = {}
    for result in positive_results:
        method = result.split('\n')[2].split(":")[1].strip()
        if method not in method_results:
            method_results[method] = []
        method_results[method].append(result)
    
    for method in sorted(method_results.keys()):
        for res in method_results[method]:
            print(res)

    # Write the results to the file if an output file is specified
    if output_file:
        method_results = {}
        for result in output_results:
            method = result.split('\n')[2].split(":")[1].strip()
            if method not in method_results:
                method_results[method] = []
            method_results[method].append(result)

        with open(output_file, "a") as f:
            for method in sorted(method_results.keys()):
                for res in method_results[method]:
                    f.write(res + "\n")

def test_url(url, method, min_length, exclude_length, headers, body, cookie, verbose, proxy=None, insecure=False, output_file=None):
    """
    Executes a single HTTP request with the given parameters and prints the result.
    Also returns the response length.
    """
    try:
        # Proxy configuration
        proxies = {'http': proxy, 'https': proxy} if proxy else None

        # Parse cookie
        cookies = parse_cookies(cookie)
        
        response = requests.request(
            method,
            url,
            headers=headers,
            data=body,
            cookies=cookies,  # Use parsed cookies
            proxies=proxies,
            verify=not insecure # Ignore SSL verification if the "insecure" flag is enabled. "Verify" is equal to False if "insecure" is true, otherwise it is equal to True.
        )
        response_length = len(response.content)  # Get the length of the response content
        return print_status(method, str(response.status_code), url, min_length, exclude_length, headers, cookies, body, verbose, response_length, output_file)
    except requests.RequestException as e:
        if verbose:
            print(f"[+] [ {method} ] {url} - \033[0;31mError: {e}\033[0m")
        
        if output_file:
            with open(output_file,"a") as f:
                f.write(f"[+] [ {method} ] {url} - Error: {e}")
        
        return 0

def forbidden_bypass(target_url, headers, body, cookie, methods, verbose, min_length, exclude_length, num_threads, proxy, insecure, level, all, output_file=None):
    """
    Performs fuzz testing across various HTTP methods, headers, and URL fuzzing using multithreading.
    """

    # Load fuzz paths from files
    fuzz_paths = load_list_from_file(parent_dir / "data" / "fuzz_paths.txt")
    appended_fuzz_paths = load_list_from_file(parent_dir / "data" / "appended_fuzz_paths.txt")
    params = load_list_from_file(parent_dir / "data" / "params.txt")
    default_headers = load_list_from_file(parent_dir / "data" / "default_headers.txt")

    success_count = 0

    urls_to_test = set()

    # Generate all URLs to test
    for method in methods:
        headers_dict = parse_headers(headers) if headers else CaseInsensitiveDict()

        # Standard URLs
        urls_to_test.add(target_url)
        urls_to_test.add(target_url.rstrip('/') if target_url.endswith('/') else target_url + '/')

        # Fuzz paths (internal fuzzing)
        parsed_url = urlparse(target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path_parts = parsed_url.path.split('/')
        for fuzz in fuzz_paths:
            for i in range(1, len(path_parts) + 1):
                if i == 1:
                    fuzzed_url = f"{base_url}{'/'.join(path_parts[1:i])}/{fuzz}/{'/'.join(path_parts[i:])}"
                else:
                    fuzzed_url = f"{base_url}/{'/'.join(path_parts[1:i])}/{fuzz}/{'/'.join(path_parts[i:])}"
                urls_to_test.add(fuzzed_url)
                urls_to_test.add(fuzzed_url.rstrip('/') if fuzzed_url.endswith('/') else fuzzed_url + '/')

        # Appended fuzz paths
        for fuzz in appended_fuzz_paths:
            urls_to_test.add(target_url + fuzz)
            urls_to_test.add((target_url.rstrip('/') if target_url.endswith('/') else target_url) + fuzz)

        # Protocol switching
        parsed_url = urlparse(target_url)
        if (parsed_url.scheme == 'https'):
            urls_to_test.add(urlunparse(('http', parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)))
        elif (parsed_url.scheme == 'http'):
            urls_to_test.add(urlunparse(('https', parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)))
        
        # Uppercase Path
        path_parts = parsed_url.path.strip('/').split('/')

        for i in range(len(path_parts)):
            temp_path = path_parts[:]
            temp_path[i] = temp_path[i].upper()
            uppercase_url = f"{base_url}/{'/'.join(temp_path)}"
            urls_to_test.add(uppercase_url)
            urls_to_test.add(uppercase_url.rstrip('/') if uppercase_url.endswith('/') else uppercase_url + '/')

        if (all or level>2):
            for i in range(len(path_parts)):
                temp_path = path_parts[:]
                for variation in generate_case_variations(path_parts[i]):
                    temp_path[i] = variation
                    case_variation_url = f"{base_url}/{'/'.join(temp_path)}"
                    urls_to_test.add(case_variation_url)
                    urls_to_test.add(case_variation_url.rstrip('/') if case_variation_url.endswith('/') else case_variation_url + '/')
        

    # Multithreading for all URLs
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Add multithreaded tasks for default headers
        futures = []
        if (all or level>1):
            for method in methods:
                for header in default_headers:
                    header_parts = header.split(':', 1)
                    if len(header_parts) == 2:
                        # For each header, we create a new task
                        headers_dict = parse_headers(headers) if headers else CaseInsensitiveDict()
                        headers_dict[header_parts[0].strip()] = header_parts[1].strip()

                        # Test both the original and alternate URL versions concurrently
                        futures.append(executor.submit(test_url, target_url, method, min_length, exclude_length, headers_dict, body, cookie, verbose, proxy, insecure, output_file))
                        futures.append(executor.submit(test_url, target_url.rstrip('/') if target_url.endswith('/') else target_url + '/', method, min_length, exclude_length, headers_dict, body, cookie, verbose, proxy, insecure, output_file))

        # Add multithreaded tasks for fuzzed URLs
        for url in urls_to_test:
            for method in methods:
                futures.append(executor.submit(test_url, url, method, min_length, exclude_length, parse_headers(headers), body, cookie, verbose, proxy, insecure, output_file))

        for param in params:
            for method in methods:
                futures.append(executor.submit(test_url, target_url+"?"+param, method, min_length, exclude_length, parse_headers(headers), body, cookie, verbose, proxy, insecure, output_file))
                futures.append(executor.submit(test_url, target_url.rstrip('/') if target_url.endswith('/') else target_url + '/' + "?" + param, method, min_length, exclude_length, parse_headers(headers), body, cookie, verbose, proxy, insecure, output_file))

        # Collect the results as tasks complete
        for future in as_completed(futures):
            success_count += future.result()

    return success_count