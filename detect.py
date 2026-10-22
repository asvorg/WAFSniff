#!/usr/bin/env python3

import argparse
import re
import sys
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from urllib.parse import urlparse


USER_AGENT = "WAF-Detection-Tool/1.0"


# Vendor fingerprints.
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {
            "server": [r"cloudflare"],
            "cf-ray": [r".+"],
        },
        "cookies": [
            "__cf_bm",
            "cf_clearance",
        ],
        "body": [
            r"cloudflare ray id",
            r"attention required! \| cloudflare",
        ],
    },

    "Akamai": {
        "headers": {
            "server": [r"akamai"],
            "akamai-grn": [r".+"],
            "x-akamai-transformed": [r".+"],
        },
        "cookies": [
            "ak_bmsc",
            "bm_sv",
            "akacd",
        ],
        "body": [
            r"reference #[0-9a-f.]+",
            r"akamai.*reference",
        ],
    },

    "Imperva / Incapsula": {
        "headers": {
            "x-iinfo": [r".+"],
            "x-cdn": [r"imperva|incapsula"],
        },
        "cookies": [
            "incap_ses",
            "visid_incap",
        ],
        "body": [
            r"incapsula incident id",
            r"powered by incapsula",
            r"imperva",
        ],
    },

    "Sucuri": {
        "headers": {
            "server": [r"sucuri"],
            "x-sucuri-id": [r".+"],
            "x-sucuri-cache": [r".+"],
        },
        "cookies": [
            "sucuri_cloudproxy_uuid",
        ],
        "body": [
            r"sucuri website firewall",
            r"access denied.*sucuri",
        ],
    },

    "F5 BIG-IP / Advanced WAF": {
        "headers": {
            "server": [r"big-?ip"],
        },
        "cookies": [
            "bigipserver",
            "ts",
        ],
        "body": [
            r"the requested url was rejected",
            r"support id.*big-ip",
        ],
    },

    "AWS WAF": {
        "headers": {},
        "cookies": [],
        "body": [
            r"request blocked",
            r"aws waf",
        ],
    },
}


# Generic indicators that may suggest filtering, but are not
# sufficient on their own to establish that a WAF is present.
GENERIC_BLOCK_PATTERNS = [
    r"access denied",
    r"request blocked",
    r"your request has been blocked",
    r"web application firewall",
    r"security policy violation",
    r"automated requests are not allowed",
]


def normalize_url(value):
    """Validate and normalize a target URL."""

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: missing hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported.")

    return value


def fetch_target(url, timeout=10):
    """Fetch a page without sending attack payloads."""

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            return {
                "status": response.status,
                "url": response.geturl(),
                "headers": response.headers,
                "body": response.read(512 * 1024).decode(
                    "utf-8",
                    errors="replace",
                ),
            }

    except urllib.error.HTTPError as exc:
        # HTTP errors can still contain useful WAF fingerprints.
        return {
            "status": exc.code,
            "url": exc.geturl(),
            "headers": exc.headers,
            "body": exc.read(512 * 1024).decode(
                "utf-8",
                errors="replace",
            ),
        }


def parse_cookies(headers):
    """Extract cookie names from Set-Cookie response headers."""

    cookie_names = set()

    for header in headers.get_all("Set-Cookie", []):
        cookie = SimpleCookie()

        try:
            cookie.load(header)
            cookie_names.update(cookie.keys())
        except Exception:
            continue

    return {name.lower() for name in cookie_names}


def detect_waf(response):
    """Match response fingerprints against known WAF vendors."""

    headers = {
        key.lower(): value.lower()
        for key, value in response["headers"].items()
    }

    cookies = parse_cookies(response["headers"])
    body = response["body"].lower()

    vendor_evidence = {}
    generic_evidence = []

    for vendor, signatures in WAF_SIGNATURES.items():
        evidence = []

        # Match vendor-specific response headers.
        for header, patterns in signatures["headers"].items():
            value = headers.get(header, "")

            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    evidence.append(f"Header: {header}")
                    break

        # Match known vendor-specific cookie names.
        for cookie_name in signatures["cookies"]:
            if any(
                name == cookie_name
                or name.startswith(cookie_name)
                for name in cookies
            ):
                evidence.append(f"Cookie: {cookie_name}")

        # Match recognizable vendor-specific response content.
        for pattern in signatures["body"]:
            if re.search(pattern, body, re.IGNORECASE):
                evidence.append(f"Body pattern: {pattern}")

        if evidence:
            vendor_evidence[vendor] = evidence

    # Generic indicators are deliberately not vendor fingerprints.
    for pattern in GENERIC_BLOCK_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            generic_evidence.append(pattern)

    return vendor_evidence, generic_evidence


def main():
    parser = argparse.ArgumentParser(
        description="Passively detect common WAF fingerprints."
    )

    parser.add_argument(
        "url",
        help="Target website URL or hostname",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    if args.timeout < 1 or args.timeout > 60:
        parser.error("--timeout must be between 1 and 60 seconds")

    try:
        url = normalize_url(args.url)
        response = fetch_target(url, args.timeout)

    except (ValueError, urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"[!] Request failed: {exc}")
        sys.exit(1)

    vendors, generic = detect_waf(response)

    print("\n========== WAF DETECTION REPORT ==========")
    print(f"Target:       {url}")
    print(f"Final URL:    {response['url']}")
    print(f"HTTP Status:  {response['status']}")
    print(f"Server:       {response['headers'].get('Server', 'Unknown')}")

    print("\n--- Detection Results ---")

    if vendors:
        for vendor, evidence in vendors.items():
            print(f"\n[+] Possible WAF: {vendor}")

            for item in evidence:
                print(f"    - {item}")

        if any(
            len(evidence) >= 2
            for evidence in vendors.values()
        ):
            print("\nAssessment: WAF fingerprints detected.")
        else:
            print("\nAssessment: Possible WAF detected; verify manually.")

    elif generic:
        print("[?] Generic security or blocking indicators detected.")

        for item in generic:
            print(f"    - {item}")

        print("Assessment: Inconclusive; these indicators are not WAF-specific.")

    else:
        print("[-] No recognized WAF fingerprints detected.")
        print("Assessment: Inconclusive; a WAF may still be present.")

    print("\n==========================================")
    print("Note: Fingerprints are indicators, not proof.")
    print("==========================================\n")


if __name__ == "__main__":
    main()
