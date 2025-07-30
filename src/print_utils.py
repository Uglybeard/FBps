import threading
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

class ResultType(Enum):
    SUCCESS = "Successful bypass"
    REDIRECT = "Redirect (potential bypass)"
    BLOCKED = "Blocked (expected)"
    SERVER_ERROR = "Server error"
    NETWORK_ERROR = "Network/parsing error"

@dataclass
class HTTPResult:
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
            'error_message': self.error_message
        }

class Colors:
    GREEN = "\033[0;32m"
    YELLOW = "\033[93m"
    RED = "\033[0;31m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    DARK_PURPLE = "\033[38;5;53m"


class OutputFormatter:
    # Display mappings
    SYMBOLS = {
        ResultType.SUCCESS: "[+]",
        ResultType.REDIRECT: "[?]",
        ResultType.BLOCKED: "[-]", 
        ResultType.SERVER_ERROR: "[!]",
        ResultType.NETWORK_ERROR: "[X]"
    }
    
    COLORS = {
        ResultType.SUCCESS: Colors.GREEN,
        ResultType.REDIRECT: Colors.YELLOW,
        ResultType.BLOCKED: Colors.RED,
        ResultType.SERVER_ERROR: Colors.PURPLE,
        ResultType.NETWORK_ERROR: Colors.DARK_PURPLE
    }
    
    @staticmethod
    def determine_result_type(status_code: int, error_message: Optional[str] = None) -> ResultType:
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
        symbol = cls.SYMBOLS[result.result_type]
        
        if colored:
            color = cls.COLORS[result.result_type]
            status_str = f"{color}{result.status_code}{Colors.RESET}"
            symbol_str = f"{color}{symbol}{Colors.RESET}"
        else:
            status_str = str(result.status_code)
            symbol_str = symbol
        
        # Truncate long URLs
        url_display = result.url[:57] + "..." if len(result.url) > 60 else result.url
        headers_brief = cls._format_headers_brief(result.headers)
        
        return (
            f"{symbol_str} {result.method:<8} | {status_str:>3} | "
            f"Len: {result.response_length:<6} | {url_display:<60} | "
            f"Headers: {headers_brief}"
        )
    
    @classmethod
    def format_detailed(cls, result: HTTPResult, colored: bool = True) -> str:
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
        
        return "\n".join(lines)
    
    @staticmethod
    def _format_headers_brief(headers: Optional[Dict]) -> str:
        if not headers:
            return "{}"
        if len(headers) <= 2:
            return str(dict(headers))
        first_key = list(headers.keys())[0]
        return f"{{{first_key}: ..., +{len(headers)-1} more}}"

class ResultManager:
    def __init__(self):
        self._results: List[HTTPResult] = []
        self._lock = threading.Lock()
        self.formatter = OutputFormatter()
    
    def add_result(self, method: str, status_code: int, url: str, response_length: int,
                  headers: Optional[Dict] = None, cookies: Optional[Dict] = None, 
                  body: Optional[str] = None, error_message: Optional[str] = None,
                  min_length: Optional[int] = None, exclude_lengths: Optional[List[int]] = None,
                  verbose: bool = False, output_file: Optional[str] = None) -> int:
        
        # Create result
        result_type = self.formatter.determine_result_type(status_code, error_message)
        result = HTTPResult(
            method=method, url=url, status_code=status_code, response_length=response_length,
            headers=headers or {}, cookies=cookies or {}, body=body, 
            result_type=result_type, timestamp=time.time(), error_message=error_message
        )
        
        # Apply filters
        if min_length and response_length < min_length:
            return 0
        if exclude_lengths and response_length in exclude_lengths:
            return 0
        
        # Store result thread-safely
        with self._lock:
            self._results.append(result)
        
        # Print verbose output
        if verbose:
            if error_message:
                print(f"{Colors.DARK_PURPLE}[X] {method} {url} - Error: {error_message}{Colors.RESET}")
            else:
                print(self.formatter.format_compact(result, colored=True))
        
        # Write to file
        if output_file:
            self._write_to_file(result, output_file)
        
        return 1 if result_type == ResultType.SUCCESS else 0
    
    def print_summary(self) -> None:
        with self._lock:
            results = self._results.copy()
        
        if not results:
            print("\nNo results to display.")
            return
        
        # Print statistics
        self._print_statistics(results)
        
        # Print successful bypasses grouped by method
        successful = [r for r in results if r.result_type == ResultType.SUCCESS]
        if not successful:
            print(f"\n{Colors.BOLD}No successful bypasses found.{Colors.RESET}")
            return
        
        print(f"\n{Colors.BOLD}SUCCESSFUL BYPASSES:{Colors.RESET}")
        
        # Group by method
        by_method = {}
        for result in successful:
            by_method.setdefault(result.method, []).append(result)
        
        for method in sorted(by_method.keys()):
            for result in by_method[method]:
                print(self.formatter.format_detailed(result, colored=True))
    
    def export_json(self, filename: str) -> None:
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
        
        # Categorize results
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
        
        # Create summary metadata
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
        
        with open(filename, 'w') as f:
            json.dump(summary, f, indent=2)
    
    def get_stats(self) -> Dict[str, Any]:
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
        stats = self.get_stats()
        
        print(f"\n{Colors.BOLD}SCAN SUMMARY:{Colors.RESET}")
        print(f"Total requests: {stats['total_requests']}")
        print(f"Successful bypasses: {Colors.GREEN}{stats['successful_bypasses']}{Colors.RESET}")
        
        if stats['total_requests'] > 0:
            success_rate = (stats['successful_bypasses'] / stats['total_requests']) * 100
            print(f"Success rate: {success_rate:.2f}%")
        
        print(f"\n{Colors.BOLD}Result breakdown:{Colors.RESET}")
        
        # Combined legend with counts
        result_mappings = [
            (ResultType.SUCCESS, Colors.GREEN, "[+] 2xx"),
            (ResultType.REDIRECT, Colors.YELLOW, "[?] 3xx"), 
            (ResultType.BLOCKED, Colors.RED, "[-] 4xx"),
            (ResultType.SERVER_ERROR, Colors.PURPLE, "[!] 5xx"),
            (ResultType.NETWORK_ERROR, Colors.DARK_PURPLE, "[X] Error")
        ]
        
        for result_type, color, symbol_desc in result_mappings:
            count = stats['by_result_type'].get(result_type.value, 0)
            if count > 0:  # Only show categories that have results
                print(f"  {color}{symbol_desc} - {result_type.value}: {count}{Colors.RESET}")
        
        # Show empty categories in gray if no results
        empty_categories = [
            (result_type, symbol_desc) for result_type, _, symbol_desc in result_mappings
            if stats['by_result_type'].get(result_type.value, 0) == 0
        ]
        
        if empty_categories:
            print(f"\n{Colors.BOLD}Legend (no results):{Colors.RESET}")
            for result_type, symbol_desc in empty_categories:
                print(f"  {symbol_desc} - {result_type.value}")

    
    def _write_to_file(self, result: HTTPResult, output_file: str) -> None:
        # Only write to JSON file, no more TXT logging
        pass  # Remove all file writing during verbose mode

# Global instance for backward compatibility
_manager = ResultManager()

# Backward compatible API
def print_status(method, status, url, min_length, exclude_lengths, headers="", cookies="", body="", verbose=False, response_length=0, output_file=None):
    return _manager.add_result(
        method=method, status_code=int(status), url=url, response_length=response_length,
        headers=headers, cookies=cookies, body=body, min_length=min_length,
        exclude_lengths=exclude_lengths, verbose=verbose, output_file=output_file
    )

def log_error(method, url, error, output_file=None):
    _manager.add_result(
        method=method, status_code=0, url=url, response_length=0,
        error_message=str(error), output_file=output_file
    )
    return f"{Colors.DARK_PURPLE}[X] {method} {url} - Error: {error}{Colors.RESET}"

def print_ordered_results(output_file=None):
    _manager.print_summary()
    if output_file:
        # Export to JSON only if output file is specified
        _manager.export_json(output_file)
        print(f"\n{Colors.CYAN}Results exported to: {output_file}{Colors.RESET}")

def get_manager() -> ResultManager:
    return _manager