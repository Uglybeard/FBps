import argparse

def parse_arguments():
    """
    Parses command-line arguments for the script.
    Returns an argparse.Namespace object with all the arguments.
    """
    parser = argparse.ArgumentParser(description="FBps (Forbidden Bypass) is a fuzzing script designed for bypassing HTTP status codes 403 and 401.")
    parser.add_argument("-m", "--method", default="GET", help="Specify one or more HTTP methods, separated by commas (e.g., GET,POST,HEAD). The default method is GET.")
    parser.add_argument("-H", "--header", action="append", help="Specify headers in 'Key: Value' format")
    parser.add_argument("-b", "--body", help="Specify the request body")
    parser.add_argument("-c", "--cookies", help="Specify cookies")
    parser.add_argument("-A", "--all", action="store_true", help="Perform all tests with common HTTP methods")
    parser.add_argument("-L", "--level", type=int, default=1, help="Level of tests to perform (1-3, default 1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Specify an output file to save the results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Specify number of threads (default: 5)")
    parser.add_argument("-p", "--proxy", help="Specify SOCKS proxy (format: socks5h://user:pass@host:port)")
    parser.add_argument("--min-length", type=int, help="Skip responses with a length less than the specified value")
    parser.add_argument("--insecure", action="store_true", help="Skip SSL certificate verification and suppress related warnings")
    parser.add_argument("url", help="The target URL")
    return parser.parse_args()