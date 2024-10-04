from requests.structures import CaseInsensitiveDict
import itertools

def load_list_from_file(filename):
    """
    Loads a list of strings from a file, with each string separated by a newline.
    """
    try:
        with open(filename, 'r') as file:
            return [line.rstrip('\n') for line in file.readlines()]
    except FileNotFoundError:
        print(f"[!] File '{filename}' not found.")
        return []

def generate_case_variations(s):
    """
    Generates all upper and lower case combinations for a string.
    """
    return map(''.join, itertools.product(*([char.lower(), char.upper()] for char in s)))

def parse_headers(headers_list):
    """
    Parses a list of header strings into a CaseInsensitiveDict.
    """
    headers_dict = CaseInsensitiveDict()
    if headers_list is None:
        return headers_dict

    for header in headers_list:
        header_parts = header.split(":", 1)
        if len(header_parts) == 2:
            headers_dict[header_parts[0].strip()] = header_parts[1].strip()
        else:
            print(f"Invalid header format: {header}")
    return headers_dict

def parse_cookies(cookie_string):
    """Parses a cookie string into a dictionary."""
    cookies = {}
    if cookie_string:
        # Split the string by semicolons to handle multiple cookies
        cookie_parts = cookie_string.split(';')
        for part in cookie_parts:
            # Split each part by the first '=' to get the key and value
            key_value = part.split('=', 1)
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip()
                cookies[key] = value
    return cookies
