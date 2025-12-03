import time
import warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse

from src.banner import show_banner
from src.arg_parser import parse_arguments
from src.http_fuzz import forbidden_bypass, print_ordered_results


def main():
    """
    Entry point for FBps: parse arguments, run the fuzzing engine and print results.
    """
    # Parse command line arguments
    args = parse_arguments()
    target_url = args.url
    headers = args.header
    body = args.body
    cookie = args.cookies
    verbose = args.verbose
    num_threads = args.threads
    proxy = args.proxy
    insecure = args.insecure
    all = args.all
    output_file = args.output
    level = args.level
    min_length = args.min_length
    exclude_length = args.exclude_length

    # If no scheme is provided, default to HTTPS
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url

    # Suppress TLS verification warnings if insecure mode is enabled
    if insecure:
        warnings.simplefilter("ignore", InsecureRequestWarning)

    # Common HTTP methods to test when -A/--all is set
    # FOO is an invalid/custom method used to test method handling on the server side
    common_methods = ['GET', 'POST', 'HEAD', 'PUT', 'OPTIONS', 'PATCH', 'FOO']

    # Determine which methods to test
    if all:
        methods = common_methods
    else:
        methods = [m.strip().upper() for m in args.method.split(",")]

    # Print banner and start timer
    show_banner(num_threads)
    start_time = time.time()

    # Run the main fuzzing routine
    success_count = forbidden_bypass(
        target_url,
        headers,
        body,
        cookie,
        methods,
        verbose,
        min_length,
        exclude_length,
        num_threads,
        proxy,
        insecure,
        level,
        all,
        output_file,
    )

    # Print summary of bypasses and total execution time
    end_time = time.time()
    execution_time = round(end_time - start_time, 2)

    if verbose:
        print("=" * 80)

    if success_count > 1:
        print(f"{success_count} bypasses found in {execution_time} seconds")
    else:
        print(f"{success_count} bypass found in {execution_time} seconds")

    # Print ordered results and optionally export JSON report
    print_ordered_results(output_file)


if __name__ == "__main__":
    main()
