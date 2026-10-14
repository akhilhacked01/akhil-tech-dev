#!/usr/bin/env python3
"""
ATD Recon - Passive reconnaissance helper for authorized bug bounty work.
Developer: Akhil Tech Developer (ATD)

Python 3.9+
Install: python -m pip install requests
Run: python atd_recon.py example.com
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency. Install it with: python -m pip install requests")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing dependency. Install it with: python -m pip install colorama")
    sys.exit(1)

TIMEOUT = 8
HEADERS = {"User-Agent": "ATD-Recon/1.0 (passive security checks)"}


def normalize_domain(value):
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].strip().lower().rstrip(".")
    if not value or "." not in value or any(c.isspace() for c in value):
        raise ValueError("Enter a valid domain, e.g. example.com")
    return value


def dns_lookup(domain):
    result = {"hostname": domain, "addresses": [], "error": None}
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        result["addresses"] = sorted({item[4][0] for item in infos})
    except socket.gaierror as exc:
        result["error"] = str(exc)
    return result


def tls_info(domain):
    result = {"available": False, "error": None}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure:
                cert = secure.getpeercert()
                result.update({
                    "available": True,
                    "tls_version": secure.version(),
                    "cipher": secure.cipher()[0] if secure.cipher() else None,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [
                        name for kind, name in cert.get("subjectAltName", [])
                        if kind == "DNS"
                    ],
                })
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        result["error"] = str(exc)
    return result


def get_url(url):
    try:
        response = requests.get(
            url, headers=HEADERS, timeout=TIMEOUT,
            allow_redirects=True, stream=True
        )
        data = {
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
        }
        response.close()
        return data
    except requests.RequestException as exc:
        return {"requested_url": url, "error": str(exc)}


def security_headers(domain):
    result = {"url": None, "status_code": None, "headers": {}, "missing": []}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            response = requests.get(
                url, headers=HEADERS, timeout=TIMEOUT,
                allow_redirects=True, stream=True
            )
            result["url"] = response.url
            result["status_code"] = response.status_code
            wanted = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            result["headers"] = {
                key: response.headers.get(key) for key in wanted
                if response.headers.get(key) is not None
            }
            result["missing"] = [
                key for key in wanted if key not in result["headers"]
            ]
            response.close()
            return result
        except requests.RequestException:
            continue
    result["error"] = "Could not fetch the website over HTTP or HTTPS."
    return result


def public_subdomains(domain):
    """Query public certificate-transparency data; no active probing."""
    url = "https://crt.sh/"
    try:
        response = requests.get(
            url, params={"q": f"%.{domain}", "output": "json"},
            headers=HEADERS, timeout=15
        )
        if response.status_code != 200:
            return {"source": url, "names": [], "error": f"HTTP {response.status_code}"}
        records = response.json()
        names = set()
        for record in records:
            for name in record.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    if "*" not in name and " " not in name:
                        names.add(name)
        return {"source": url, "names": sorted(names), "note": "Certificate records are historical and do not prove a host is live."}
    except (requests.RequestException, ValueError) as exc:
        return {"source": url, "names": [], "error": str(exc)}


def show_banner():
    print(Fore.GREEN + Style.BRIGHT + r"""
     █████╗ ████████╗██████╗
    ██╔══██╗╚══██╔══╝██╔══██╗
    ███████║   ██║   ██║  ██║
    ██╔══██║   ██║   ██║  ██║
    ██║  ██║   ██║   ██████╔╝
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝
""" + Style.RESET_ALL)
    print(Fore.CYAN + Style.BRIGHT + "       ATD RECON | AKHIL TECH DEVELOPER")
    print(Fore.YELLOW + "       Passive Reconnaissance Tool v1.1")
    print(Fore.GREEN + "  " + "─" * 46 + Style.RESET_ALL)


def get_domain_input():
    show_banner()
    print(Fore.CYAN + "  Test only a domain you own or are authorized to assess.")
    print(Fore.GREEN + "  ┌" + "─" * 42 + "┐")
    print(Fore.GREEN + "  │ " + Fore.WHITE + Style.BRIGHT + "ATD TARGET INPUT" + " " * 25 + Fore.GREEN + "│")
    print(Fore.GREEN + "  └" + "─" * 42 + "┘")
    try:
        value = input(Fore.YELLOW + "  ATD > " + Fore.WHITE).strip()
        return normalize_domain(value)
    except ValueError as exc:
        print(Fore.RED + f"  Invalid domain: {exc}")
        sys.exit(1)
    except EOFError:
        print(Fore.RED + "\\n  Input cancelled.")
        sys.exit(1)


def run_recon(domain):
    print("\\n" + Fore.GREEN + "=" * 54)
    print(Fore.CYAN + Style.BRIGHT + " ATD RECON | Akhil Tech Developer")
    print(Fore.GREEN + "=" * 54 + Style.RESET_ALL)
    print(Fore.YELLOW + f"Target: {domain}")
    print("Mode: passive DNS, public certificate records, basic HTTP checks")
    print("")

    report = {
        "tool": "ATD Recon",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": domain,
        "scope_note": "Run only against domains you own or are authorized to assess.",
    }

    print("[1/5] DNS lookup...")
    report["dns"] = dns_lookup(domain)
    print("      IPs:", ", ".join(report["dns"]["addresses"]) or "not found")

    print("[2/5] TLS certificate...")
    report["tls"] = tls_info(domain)
    print("      TLS:", report["tls"].get("tls_version") or report["tls"].get("error", "unavailable"))

    print("[3/5] HTTP security headers...")
    report["security_headers"] = security_headers(domain)
    sh = report["security_headers"]
    print("      HTTP status:", sh.get("status_code", "unknown"))
    print("      Missing common headers:", ", ".join(sh.get("missing", [])) or "none detected")

    print("[4/5] robots.txt and sitemap.xml...")
    report["well_known_files"] = {
        "robots_txt": get_url(f"https://{domain}/robots.txt"),
        "sitemap_xml": get_url(f"https://{domain}/sitemap.xml"),
    }
    for key, item in report["well_known_files"].items():
        print(f"      {key}: HTTP {item.get('status_code', 'unknown')}")

    print("[5/5] Public certificate-transparency subdomains...")
    report["subdomains"] = public_subdomains(domain)
    names = report["subdomains"].get("names", [])
    print(f"      Found {len(names)} DNS names in public certificate records")

    safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain)
    filename = f"atd_recon_{safe_name}.json"
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print("\nDone. JSON report saved to:", filename)
    print("Reminder: findings need manual verification; missing headers alone do not prove a vulnerability.")
    return report


def main():
    parser = argparse.ArgumentParser(
        description="ATD Recon: passive reconnaissance for authorized bug bounty testing."
    )
    parser.add_argument(
        "domain", nargs="?",
        help="Target domain, e.g. example.com (omit to use the input box)"
    )
    args = parser.parse_args()
    if args.domain:
        try:
            domain = normalize_domain(args.domain)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        domain = get_domain_input()
    run_recon(domain)


if __name__ == "__main__":
    main()
