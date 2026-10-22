# WAFSniff

A simple barebones WAF detection tool built in Python. It performs a passive HTTP request to a target site and inspects the response for common vendor fingerprints, including headers, cookies, and response-body patterns.

## What it detects

WAFSniff looks for common indicators associated with:

- Cloudflare
- Akamai
- Imperva / Incapsula
- Sucuri
- F5 BIG-IP / Advanced WAF
- AWS WAF

It also reports generic blocking phrases such as "access denied" or "request blocked" when a site appears to be enforcing security controls, even when the underlying vendor cannot be identified confidently.

## Features

- Passive detection only (no attack payloads or exploit traffic)
- Validates and normalizes target URLs
- Checks HTTP response headers, cookies, and HTML/body markers
- Prints a simple human-readable report
- Supports custom request timeout

## Requirements

- Python 3

## Usage

```bash
python3 detect.py https://example.com
```

With a custom timeout:

```bash
python3 detect.py --timeout 20 https://example.com
```

To see the available options:

```bash
python3 detect.py --help
```

## Example output

```text
========== WAF DETECTION REPORT ==========
Target:       https://example.com
Final URL:    https://example.com
HTTP Status:  200
Server:       cloudflare

--- Detection Results ---

[+] Possible WAF: Cloudflare
    - Header: server
    - Cookie: __cf_bm

Assessment: WAF fingerprints detected.

==========================================
Note: Fingerprints are indicators, not proof.
==========================================
```

## Notes and limitations

- This tool is intentionally lightweight and heuristic-based.
- A WAF may still be present even when no fingerprints are found.
- Some sites strip or rewrite headers, cookies, or response content, which may reduce detection accuracy.
- Results should be treated as hints for further investigation, not definitive proof.

## Project status

This repository is a minimal proof-of-concept WAF detection utility and is intended for reconnaissance and research use.
