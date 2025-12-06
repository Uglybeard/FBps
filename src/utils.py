from requests.structures import CaseInsensitiveDict
import random

# Hardcoded seed to ensure deterministic generation of case variations
random.seed(42)

def load_list_from_file(filename):
    """
    Load a list of strings from a file, one entry per line.

    Returns an empty list if the file does not exist.
    """
    try:
        with open(filename, 'r') as file:
            # Strip only the trailing newline to preserve other whitespace
            return [line.rstrip('\n') for line in file.readlines()]
    except FileNotFoundError:
        print(f"[!] File '{filename}' not found.")
        return []


def generate_case_variations(s):
    """
    Generate a set of case variations for the given string.

    Returns a list of unique variations.
    """
    variations = set()

    # All lowercase
    variations.add(s.lower())

    # All uppercase
    variations.add(s.upper())

    # First character uppercase, rest lowercase
    if s:
        variations.add(s[0].upper() + s[1:].lower())

    # Last character uppercase, rest lowercase
    if s:
        variations.add(s[:-1].lower() + s[-1].upper())

    # Random mixed case variant
    random_case = ''.join(random.choice([char.lower(), char.upper()]) for char in s)
    variations.add(random_case)

    return list(variations)


def parse_headers(headers_list):
    """
    Parse a list of HTTP header strings ("Name: Value") into a CaseInsensitiveDict. Invalid entries are reported and ignored.

    Returns a CaseInsensitiveDict of headers.
    """
    headers_dict = CaseInsensitiveDict()
    if headers_list is None:
        return headers_dict

    for header in headers_list:
        header_parts = header.split(":", 1)
        if len(header_parts) == 2:
            name = header_parts[0].strip()
            value = header_parts[1].strip()
            headers_dict[name] = value
        else:
            print(f"Invalid header format: {header}")

    return headers_dict


def parse_cookies(cookie_string):
    """
    Parse a cookie header string ("key1=value1; key2=value2; ...") into a plain dictionary.

    Returns a dictionary of cookies.
    """
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
