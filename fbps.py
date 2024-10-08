import time
import warnings
from urllib3.exceptions import InsecureRequestWarning
from src.banner import show_banner
from src.arg_parser import parse_arguments
from src.http_fuzz import forbidden_bypass, print_ordered_results

def main():
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

    # Suppress InsecureRequestWarning if insecure
    if(insecure):
        warnings.simplefilter('ignore', InsecureRequestWarning)

    # List of common HTTP methods to use when -A option is set
    common_methods = ['GET', 'POST', 'HEAD', 'PUT', 'OPTIONS', 'PATCH', 'FOO'] # FOO is a non-existing method

    # Determine which methods to test
    if all:
        methods = common_methods
    else:
        methods = [m.strip().upper() for m in args.method.split(",")]

    # Print banner
    show_banner(num_threads)
    start_time = time.time()
    
    # Perform fuzz testing across all HTTP methods
    success_count = forbidden_bypass(target_url, headers, body, cookie, methods, verbose, min_length, num_threads, proxy, insecure, level, all, output_file)

    # Print the number of bypasses found and the time taken
    end_time = time.time()
    execution_time = round(end_time - start_time, 2)
    if verbose:
        print("=" * 80)

    if success_count > 1:
        print(f"{success_count} bypasses found in {execution_time} seconds")
    else:
        print(f"{success_count} bypass found in {execution_time} seconds")

    # Print positive results
    print_ordered_results(output_file)


if __name__ == "__main__":
    main()
