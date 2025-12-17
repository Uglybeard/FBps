import threading
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class ResultType(Enum):
    """
    High-level classification of HTTP results based on status code or errors.
    """

    SUCCESS = "Successful bypass"
    REDIRECT = "Redirect (potential bypass)"
    BLOCKED = "Blocked (expected)"
    SERVER_ERROR = "Server error"
    NETWORK_ERROR = "Network/parsing error"


@dataclass
class HTTPResult:
    """
    Represents a single HTTP request/response pair with classification metadata.
    """

    method: str
    url: str
    status_code: int
    response_length: int
    headers: Dict[str, Any]
    cookies: Dict[str, Any]
    body: Optional[str]
    result_type: ResultType
    timestamp: float
    error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        """
        Convert the HTTPResult instance to a JSON-serializable dictionary.
        """
        return {
            'method': self.method,
            'url': self.url,
            'status_code': self.status_code,
            'response_length': self.response_length,
            'headers': dict(self.headers) if self.headers else {},
            'cookies': dict(self.cookies) if self.cookies else {},
            'body': self.body,
            'result_type': self.result_type.value,
            'timestamp': self.timestamp,
            'error_message': self.error_message,
            'reproduce': getattr(self, "reproduce", None)
        }


class Colors:
    """
    ANSI color codes used for styling console output.
    """

    GREEN = "\033[0;32m"
    YELLOW = "\033[93m"
    RED = "\033[0;31m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    DARK_PURPLE = "\033[38;5;53m"


class OutputFormatter:
    """
    Helper class responsible for formatting HTTPResult instances for display.
    """

    # Mapping of result types to short status symbols.
    SYMBOLS = {
        ResultType.SUCCESS: "[+]",
        ResultType.REDIRECT: "[?]",
        ResultType.BLOCKED: "[-]",
        ResultType.SERVER_ERROR: "[!]",
        ResultType.NETWORK_ERROR: "[X]"
    }

    # Mapping of result types to color codes.
    COLORS = {
        ResultType.SUCCESS: Colors.GREEN,
        ResultType.REDIRECT: Colors.YELLOW,
        ResultType.BLOCKED: Colors.RED,
        ResultType.SERVER_ERROR: Colors.PURPLE,
        ResultType.NETWORK_ERROR: Colors.DARK_PURPLE
    }

    @staticmethod
    def determine_result_type(status_code: int, error_message: Optional[str] = None) -> ResultType:
        """
        Determine the ResultType for a given status code and optional error message.
        """
        if error_message:
            return ResultType.NETWORK_ERROR
        elif 200 <= status_code < 300:
            return ResultType.SUCCESS
        elif 300 <= status_code < 400:
            return ResultType.REDIRECT
        elif 400 <= status_code < 500:
            return ResultType.BLOCKED
        else:
            return ResultType.SERVER_ERROR

    @classmethod
    def format_compact(cls, result: HTTPResult, colored: bool = True) -> str:
        """
        Produce a compact, single-line representation of a result.

        Intended for verbose/streaming output during scanning.
        """
        symbol = cls.SYMBOLS[result.result_type]

        if colored:
            color = cls.COLORS[result.result_type]
            status_str = f"{color}{result.status_code}{Colors.RESET}"
            symbol_str = f"{color}{symbol}{Colors.RESET}"
        else:
            status_str = str(result.status_code)
            symbol_str = symbol

        # Truncate long URLs to keep the line within a reasonable width.
        url_display = result.url[:57] + "..." if len(result.url) > 60 else result.url
        headers_brief = cls._format_headers_brief(result.headers)

        return (
            f"{symbol_str} {result.method:<8} | {status_str:>3} | "
            f"Len: {result.response_length:<6} | {url_display:<60} | "
            f"Headers: {headers_brief}"
        )

    @classmethod
    def format_detailed(cls, result: HTTPResult, colored: bool = True) -> str:
        """
        Produce a multi-line, detailed representation of a result.

        Used in the final summary for successful bypasses.
        """
        symbol = cls.SYMBOLS[result.result_type]

        if colored:
            color = cls.COLORS[result.result_type]
            status_str = f"{color}{result.status_code}{Colors.RESET}"
            header = f"{color}{symbol} {result.method:<8}{Colors.RESET}"
        else:
            status_str = str(result.status_code)
            header = f"{symbol} {result.method:<8}"

        lines = [
            "\n" + "-" * 60,
            header,
            f"    URL:        {result.url}",
            f"    Status:     {status_str}",
            f"    Length:     {result.response_length}",
            f"    Headers:    {result.headers}",
            f"    Cookies:    {result.cookies}",
            f"    Body:       {result.body or 'None'}"
        ]

        if result.error_message:
            lines.append(f"    Error:      {result.error_message}")

        reproduce = getattr(result, "reproduce", None)
        if reproduce:
            lines.append(f"    Reproduce:  {reproduce}")

        return "\n".join(lines)

    @staticmethod
    def _format_headers_brief(headers: Optional[Dict]) -> str:
        """
        Build a compact summary of the headers dictionary.

        Shows either the full dict (for small sets) or a short placeholder.
        """
        if not headers:
            return "{}"
        if len(headers) <= 2:
            return str(dict(headers))
        first_key = list(headers.keys())[0]
        return f"{{{first_key}: ..., +{len(headers)-1} more}}"


class ResultManager:
    """
    Thread-safe collector and reporter for HTTPResult instances.
    """

    def __init__(self):
        self._results: List[HTTPResult] = []
        self._lock = threading.Lock()
        self.formatter = OutputFormatter()

    def add_result(self, method: str, status_code: int, url: str, response_length: int,
                   headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                   body: Optional[str] = None, error_message: Optional[str] = None,
                   min_length: Optional[int] = None, exclude_lengths: Optional[List[int]] = None,
                   verbose: bool = False, output_file: Optional[str] = None) -> int:
        """
        Create, filter, store and optionally print a single HTTPResult.

        Returns 1 if the result is classified as SUCCESS, otherwise 0.
        """
        # Create result object and classify it.
        result_type = self.formatter.determine_result_type(status_code, error_message)
        result = HTTPResult(
            method=method,
            url=url,
            status_code=status_code,
            response_length=response_length,
            headers=headers or {},
            cookies=cookies or {},
            body=body,
            result_type=result_type,
            timestamp=time.time(),
            error_message=error_message
        )

        # Length-based filters
        if min_length and response_length < min_length:
            return 0
        if exclude_lengths and response_length in exclude_lengths:
            return 0

        # Build "reproduce" command for raw-bytes URLs
        if "\\x" in url:
            try:
                parsed = urlparse(url)
                scheme = parsed.scheme or "http"
                netloc = parsed.netloc
                path = parsed.path or "/"
                reproduce = (
                    f"curl '{scheme}://{netloc}' "
                    f"--request-target \"$(printf '{path}')\" "
                    f"-X {method}"
                )
                setattr(result, "reproduce", reproduce)
            except Exception:
                pass

        with self._lock:
            self._results.append(result)

        # Print verbose output if requested
        if verbose:
            if error_message:
                print(f"{Colors.DARK_PURPLE}[X] {method} {url} - Error: {error_message}{Colors.RESET}")
            else:
                print(self.formatter.format_compact(result, colored=True))

        return 1 if result_type == ResultType.SUCCESS else 0

    def print_summary(self) -> None:
        """
        Print an aggregated summary and detailed view of successful bypasses.
        """
        with self._lock:
            results = self._results.copy()

        if not results:
            print("\nNo results to display.")
            return

        # Print high-level statistics and breakdown
        self._print_statistics(results)

        # Extract successful bypasses
        successful = [r for r in results if r.result_type == ResultType.SUCCESS]
        if not successful:
            print(f"\n{Colors.BOLD}No successful bypasses found.{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}SUCCESSFUL BYPASSES:{Colors.RESET}")

        # Group successful results by HTTP method
        by_method: Dict[str, List[HTTPResult]] = {}
        for result in successful:
            by_method.setdefault(result.method, []).append(result)

        # Print detailed output grouped by method
        for method in sorted(by_method.keys()):
            for result in by_method[method]:
                print(self.formatter.format_detailed(result, colored=True))

    def export_json(self, filename: str) -> None:
        """
        Export all recorded results to a JSON file.

        Results are grouped by category and accompanied by scan metadata.
        """
        with self._lock:
            results = self._results.copy()

        # Group results by type with priority order
        grouped_results = {
            "successful_bypasses": [],
            "potential_bypasses": [],
            "blocked_requests": [],
            "server_errors": [],
            "network_errors": []
        }

        # Categorize results into the groups above
        for result in results:
            result_dict = result.to_dict()
            if result.result_type == ResultType.SUCCESS:
                grouped_results["successful_bypasses"].append(result_dict)
            elif result.result_type == ResultType.REDIRECT:
                grouped_results["potential_bypasses"].append(result_dict)
            elif result.result_type == ResultType.BLOCKED:
                grouped_results["blocked_requests"].append(result_dict)
            elif result.result_type == ResultType.SERVER_ERROR:
                grouped_results["server_errors"].append(result_dict)
            elif result.result_type == ResultType.NETWORK_ERROR:
                grouped_results["network_errors"].append(result_dict)

        # Build top-level summary metadata
        summary = {
            "scan_metadata": {
                "total_requests": len(results),
                "successful_bypasses": len(grouped_results["successful_bypasses"]),
                "potential_bypasses": len(grouped_results["potential_bypasses"]),
                "blocked_requests": len(grouped_results["blocked_requests"]),
                "server_errors": len(grouped_results["server_errors"]),
                "network_errors": len(grouped_results["network_errors"]),
                "scan_timestamp": time.time()
            },
            "results": grouped_results
        }

        out_path = Path(filename)
        if out_path.parent:
            out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(filename, 'w') as f:
            json.dump(summary, f, indent=2)

    def get_stats(self) -> Dict[str, Any]:
        """
        Compute basic statistics on the stored results.

        Returns a dict with total count, counts per ResultType and successful bypasses.
        """
        with self._lock:
            results = self._results.copy()

        stats = {'total_requests': len(results), 'by_result_type': {}, 'successful_bypasses': 0}

        for result in results:
            result_type = result.result_type.value
            stats['by_result_type'][result_type] = stats['by_result_type'].get(result_type, 0) + 1
            if result.result_type == ResultType.SUCCESS:
                stats['successful_bypasses'] += 1

        return stats

    def _print_statistics(self, results: List[HTTPResult]) -> None:
        """
        Print a summary of the scan, including counts and success rate.
        """
        stats = self.get_stats()

        print(f"\n{Colors.BOLD}SCAN SUMMARY:{Colors.RESET}")
        print(f"Total requests: {stats['total_requests']}")
        print(f"Successful bypasses: {Colors.GREEN}{stats['successful_bypasses']}{Colors.RESET}")

        if stats['total_requests'] > 0:
            success_rate = (stats['successful_bypasses'] / stats['total_requests']) * 100
            print(f"Success rate: {success_rate:.2f}%")

        print(f"\n{Colors.BOLD}Result breakdown:{Colors.RESET}")

        # Combined legend with counts for non-empty categories
        result_mappings = [
            (ResultType.SUCCESS, Colors.GREEN, "[+] 2xx"),
            (ResultType.REDIRECT, Colors.YELLOW, "[?] 3xx"),
            (ResultType.BLOCKED, Colors.RED, "[-] 4xx"),
            (ResultType.SERVER_ERROR, Colors.PURPLE, "[!] 5xx"),
            (ResultType.NETWORK_ERROR, Colors.DARK_PURPLE, "[X] Error")
        ]

        for result_type_enum, color, symbol_desc in result_mappings:
            count = stats['by_result_type'].get(result_type_enum.value, 0)
            if count > 0:
                print(f"  {color}{symbol_desc} - {result_type_enum.value}: {count}{Colors.RESET}")

        # Show categories with zero results as a legend section
        empty_categories = [
            (result_type_enum, symbol_desc) for result_type_enum, _, symbol_desc in result_mappings
            if stats['by_result_type'].get(result_type_enum.value, 0) == 0
        ]

        if empty_categories:
            print(f"\n{Colors.BOLD}Legend (no results):{Colors.RESET}")
            for result_type_enum, symbol_desc in empty_categories:
                print(f"  {symbol_desc} - {result_type_enum.value}")


# Global instance for backward compatibility
_manager = ResultManager()


# Backward compatible API
def print_status(method, status, url, min_length, exclude_lengths, headers="", cookies="", body="", verbose=False, response_length=0, output_file=None):
    """
    Wrapper around ResultManager.add_result used by the HTTP fuzzing logic.
    """
    return _manager.add_result(
        method=method, status_code=int(status), url=url, response_length=response_length,
        headers=headers, cookies=cookies, body=body, min_length=min_length,
        exclude_lengths=exclude_lengths, verbose=verbose, output_file=output_file
    )


def log_error(method, url, error, output_file=None):
    """
    Record a network/parsing error and return a formatted error string.
    """
    _manager.add_result(
        method=method, status_code=0, url=url, response_length=0,
        error_message=str(error), output_file=output_file
    )
    return f"{Colors.DARK_PURPLE}[X] {method} {url} - Error: {error}{Colors.RESET}"


def print_ordered_results(output_file=None):
    """
    Print the summary of results and optionally export them to a JSON file.
    """
    _manager.print_summary()
    if output_file:
       # Export to JSON only if output file is specified
        _manager.export_json(output_file)
        print(f"\n{Colors.CYAN}Results exported to: {output_file}{Colors.RESET}")


def get_manager() -> ResultManager:
    """
    Return the global ResultManager instance.

    Used by callers that need direct access to the result collection.
    """
    return _manager
