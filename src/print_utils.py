positive_results = []
output_results = []

# Constants
METHOD_COLUMN_WIDTH = 7
URL_COLUMN_WIDTH = 60
RESPONSE_LEN_COLUMN_WIDTH = 5
STATUS_COLORS = {
    "2": "\033[0;32m",
    "3": "\033[93m",
    "default": "\033[0;31m"
}
SYMBOLS = {
    "2": "[+]",
    "3": "[?]",
    "default": "[-]"
}

def get_status_color(status):
    return STATUS_COLORS.get(status[0], STATUS_COLORS["default"])

def get_symbol(status):
    return SYMBOLS.get(status[0], SYMBOLS["default"])

def log_error(method, url, error, output_file=None):
    """
    Logs an error message.
    """
    error_message = f"[!] {method} {url} - \033[0;31mError: {error}\033[0m"
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"[!] {method} {url} - Error: {error}\n")
    return error_message

def print_status(method, status, url, min_length, exclude_lengths, headers="", cookies="", body="", verbose=False, response_length=0, output_file=None):
    """
    Prints the HTTP request result, using different colors for success (2xx) and failure.
    Also prints the length of the response.
    """
    status_color = get_status_color(status)
    symbol = get_symbol(status)

    colored_line = (
        f"{symbol} {method:<{METHOD_COLUMN_WIDTH}} | {status_color}{status}\033[0m | Len: {response_length:<{RESPONSE_LEN_COLUMN_WIDTH}} | "
        f"{url:<{URL_COLUMN_WIDTH}} | Headers: {headers}"
    )

    plain_line = (
        f"{symbol} {method:<{METHOD_COLUMN_WIDTH}} | {status} | Len: {response_length:<{RESPONSE_LEN_COLUMN_WIDTH}} | "
        f"{url:<{URL_COLUMN_WIDTH}} | Headers: {headers}\n"
    )

    if verbose:
        print(colored_line)
    
    if output_file:
        with open(output_file, "a") as f:
            f.write(plain_line)

    if min_length and response_length < min_length:
        return 0
    
    if exclude_lengths and response_length in exclude_lengths:
        return 0
    
    if status.startswith("2"):
        positive_results.append(
            f"\n{'-' * 60}\n[+] Method:     {method:<{METHOD_COLUMN_WIDTH}}\n"
            f"    URL:        {url}\n"
            f"    Headers:    {headers}\n"
            f"    Cookies:    {cookies}\n"
            f"    Body:       {body}\n"
            f"    Status:     {status_color}{status}\033[0m\n"
            f"    Length:     {response_length}"
        )
        if output_file:
            output_results.append(
                f"\n{'-' * 60}\n[+] Method:     {method:<{METHOD_COLUMN_WIDTH}}\n"
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
    method_results = {}
    for result in positive_results:
        method = result.split('\n')[2].split(":")[1].strip()
        method_results.setdefault(method, []).append(result)
    
    for method in sorted(method_results.keys()):
        for res in method_results[method]:
            print(res)

    if output_file:
        method_results = {}
        for result in output_results:
            method = result.split('\n')[2].split(":")[1].strip()
            method_results.setdefault(method, []).append(result)

        with open(output_file, "a") as f:
            for method in sorted(method_results.keys()):
                for res in method_results[method]:
                    f.write(res + "\n")
