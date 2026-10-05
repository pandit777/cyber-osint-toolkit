import socket
import ssl
import json
import urllib.request
import urllib.error
import urllib.parse
import http.client
import re
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import whois


# ============================================================
# CONFIG
# ============================================================

TIMEOUT = 3
THREADS = 30

COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143,
    443, 445, 465, 587, 993, 995,
    1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443,
    9000, 9200, 27017
]

DNS_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CAA",
    "SOA"
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy"
]


# ============================================================
# DISPLAY
# ============================================================

def heading(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def line(label, value):
    print(f"{label:<28}: {value}")


# ============================================================
# DOMAIN CLEANING
# ============================================================

def clean_domain(value):

    value = value.strip()

    if not value:
        raise ValueError("Domain cannot be empty.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if not parsed.hostname:
        raise ValueError("Invalid domain.")

    return parsed.hostname.rstrip(".").lower()


# ============================================================
# IP RESOLUTION
# ============================================================

def resolve_ips(domain):

    addresses = set()

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        for result in results:
            addresses.add(result[4][0])

    except socket.gaierror:
        pass

    return sorted(addresses)


# ============================================================
# IP INFORMATION
# ============================================================

def ip_information(ip):

    heading(f"IP ADDRESS INFORMATION: {ip}")

    try:
        reverse = socket.gethostbyaddr(ip)[0]
    except Exception:
        reverse = "Unavailable"

    family = "IPv6" if ":" in ip else "IPv4"

    line("IP address", ip)
    line("Reverse DNS", reverse)
    line("IP type", family)

    try:
        url = (
            "http://ip-api.com/json/"
            + urllib.parse.quote(ip)
            + "?fields=status,message,country,regionName,"
              "city,isp,org,as"
        )

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Authorized-Recon/3.0"}
        )

        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            data = json.loads(
                response.read().decode()
            )

        if data.get("status") == "success":

            line("Country", data.get("country"))
            line("Region", data.get("regionName"))
            line("City", data.get("city"))
            line("ISP", data.get("isp"))
            line("Organization", data.get("org"))
            line("ASN", data.get("as"))

        else:
            print("IP metadata unavailable.")

    except Exception as exc:
        print("IP metadata lookup failed:", exc)


# ============================================================
# WHOIS
# ============================================================

def parse_date(value):

    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, datetime):
        return value

    return None


def whois_lookup(domain):

    heading("WHOIS DOMAIN INFORMATION")

    try:

        data = whois.whois(domain)

        creation = parse_date(
            getattr(data, "creation_date", None)
        )

        expiry = parse_date(
            getattr(data, "expiration_date", None)
        )

        updated = parse_date(
            getattr(data, "updated_date", None)
        )

        registrar = getattr(
            data,
            "registrar",
            None
        )

        status = getattr(
            data,
            "status",
            None
        )

        nameservers = getattr(
            data,
            "name_servers",
            None
        )

        line(
            "Registrar",
            registrar or "Not available"
        )

        line(
            "Creation date",
            creation or "Not available"
        )

        line(
            "Expiration date",
            expiry or "Not available"
        )

        line(
            "Last updated",
            updated or "Not available"
        )

        line(
            "Domain status",
            status or "Not available"
        )

        line(
            "Name servers",
            nameservers or "Not available"
        )

        line(
            "WHOIS server",
            getattr(data, "whois_server", None)
            or "Not available"
        )

        line(
            "DNSSEC",
            getattr(data, "dnssec", None)
            or "Not available"
        )

        if expiry:

            if expiry.tzinfo is None:
                expiry = expiry.replace(
                    tzinfo=timezone.utc
                )

            days = (
                expiry - datetime.now(
                    timezone.utc
                )
            ).days

            line(
                "Days until expiry",
                days
            )

        if creation:

            if creation.tzinfo is None:
                creation = creation.replace(
                    tzinfo=timezone.utc
                )

            age = (
                datetime.now(
                    timezone.utc
                ) - creation
            ).days

            line(
                "Domain age (days)",
                age
            )

    except Exception as exc:
        print("WHOIS lookup failed:", exc)


# ============================================================
# RDAP
# ============================================================

def rdap_lookup(domain):

    heading("RDAP REGISTRATION INFORMATION")

    try:

        url = (
            "https://rdap.org/domain/"
            + urllib.parse.quote(domain)
        )

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Authorized-Recon/3.0",
                "Accept": "application/rdap+json"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:

            data = json.loads(
                response.read().decode()
            )

        line(
            "RDAP domain",
            data.get("ldhName")
            or data.get("unicodeName")
            or domain
        )

        line(
            "Handle",
            data.get("handle", "Unavailable")
        )

        status = data.get("status", [])

        line(
            "Status",
            ", ".join(status)
            if status else "Unavailable"
        )

        nameservers = []

        for ns in data.get(
            "nameservers",
            []
        ):

            name = ns.get("ldhName")

            if name:
                nameservers.append(name)

        line(
            "Name servers",
            ", ".join(nameservers)
            if nameservers
            else "Unavailable"
        )

        for event in data.get(
            "events",
            []
        ):

            action = event.get("eventAction")
            date = event.get("eventDate")

            if action and date:
                print(
                    f"{action:<28}: {date}"
                )

    except Exception as exc:
        print("RDAP lookup failed:", exc)


# ============================================================
# DNS
# ============================================================

def dns_lookup(domain):

    heading("DNS RECORDS")

    resolver = dns.resolver.Resolver()

    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT

    records = {}

    for record_type in DNS_TYPES:

        try:

            answers = resolver.resolve(
                domain,
                record_type
            )

            values = [
                answer.to_text()
                for answer in answers
            ]

            records[record_type] = values

            print(f"\n[{record_type}]")

            for value in values:
                print(" ", value)

        except Exception:
            records[record_type] = []

            print(
                f"\n[{record_type}] "
                "No record / lookup failed"
            )

    return records


# ============================================================
# SPF / DMARC
# ============================================================

def mail_security(domain):

    heading("EMAIL SECURITY RECORDS")

    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT

    # SPF
    try:

        answers = resolver.resolve(
            domain,
            "TXT"
        )

        spf_records = []

        for answer in answers:

            text = "".join(
                answer.strings
            )

            if text.lower().startswith(
                "v=spf1"
            ):
                spf_records.append(text)

        if spf_records:

            print("\nSPF:")
            for record in spf_records:
                print(" ", record)

        else:
            print("\nSPF: Not found")

    except Exception:
        print("\nSPF: Lookup failed")

    # DMARC
    try:

        answers = resolver.resolve(
            "_dmarc." + domain,
            "TXT"
        )

        dmarc_records = []

        for answer in answers:

            text = "".join(
                answer.strings
            )

            if text.lower().startswith(
                "v=dmarc1"
            ):
                dmarc_records.append(text)

        if dmarc_records:

            print("\nDMARC:")
            for record in dmarc_records:
                print(" ", record)

        else:
            print("\nDMARC: Not found")

    except Exception:
        print("\nDMARC: Lookup failed")


# ============================================================
# TLS CERTIFICATE
# ============================================================

def tls_lookup(domain):

    heading("TLS / SSL CERTIFICATE")

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (domain, 443),
            timeout=TIMEOUT
        ) as raw:

            with context.wrap_socket(
                raw,
                server_hostname=domain
            ) as tls:

                cert = tls.getpeercert()

                line(
                    "TLS version",
                    tls.version()
                )

                line(
                    "Cipher",
                    tls.cipher()
                )

                subject = cert.get(
                    "subject",
                    []
                )

                issuer = cert.get(
                    "issuer",
                    []
                )

                def get_names(data):

                    result = []

                    for group in data:

                        for key, value in group:

                            if key in (
                                "commonName",
                                "organizationName",
                                "countryName"
                            ):

                                result.append(
                                    f"{key}={value}"
                                )

                    return ", ".join(result)

                line(
                    "Certificate subject",
                    get_names(subject)
                )

                line(
                    "Certificate issuer",
                    get_names(issuer)
                )

                line(
                    "Valid from",
                    cert.get(
                        "notBefore",
                        "Unavailable"
                    )
                )

                line(
                    "Valid until",
                    cert.get(
                        "notAfter",
                        "Unavailable"
                    )
                )

                sans = []

                for kind, value in cert.get(
                    "subjectAltName",
                    []
                ):

                    if kind == "DNS":
                        sans.append(value)

                line(
                    "DNS SANs",
                    ", ".join(sans)
                    if sans else "None"
                )

                expiry = cert.get(
                    "notAfter"
                )

                if expiry:

                    expiry_dt = datetime.strptime(
                        expiry,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    days = (
                        expiry_dt -
                        datetime.now(
                            timezone.utc
                        )
                    ).days

                    line(
                        "Certificate days left",
                        days
                    )

    except Exception as exc:
        print(
            "TLS inspection failed:",
            exc
        )


# ============================================================
# HTTP
# ============================================================

def http_request(url):

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "Mozilla/5.0 Authorized-Recon/3.0"
        },
        method="GET"
    )

    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler()
    )

    try:

        response = opener.open(
            request,
            timeout=TIMEOUT
        )

        return response

    except urllib.error.HTTPError as exc:
        return exc

    except Exception as exc:
        return exc


def http_lookup(domain):

    heading("HTTP / HTTPS INFORMATION")

    for scheme in ("https", "http"):

        url = f"{scheme}://{domain}/"

        print(f"\n[{scheme.upper()}]")

        try:

            response = http_request(url)

            if isinstance(
                response,
                Exception
            ):

                print("Error:", response)
                continue

            line(
                "Status code",
                response.status
            )

            line(
                "Final URL",
                response.geturl()
            )

            if hasattr(
                response,
                "history"
            ):
                line(
                    "Redirect count",
                    len(response.history)
                )

            headers = response.headers

            line(
                "Server",
                headers.get(
                    "Server",
                    "Not available"
                )
            )

            line(
                "Content-Type",
                headers.get(
                    "Content-Type",
                    "Not available"
                )
            )

            line(
                "Content-Length",
                headers.get(
                    "Content-Length",
                    "Not available"
                )
            )

            line(
                "Content-Encoding",
                headers.get(
                    "Content-Encoding",
                    "Not available"
                )
            )

            print("\nSecurity headers:")

            for header in SECURITY_HEADERS:

                value = headers.get(
                    header
                )

                print(
                    f"{header:<30}: "
                    f"{value or 'Not available'}"
                )

            # Cookies
            print("\nCookies:")

            cookies = headers.get_all(
                "Set-Cookie"
            )

            if cookies:

                for cookie in cookies:

                    cookie_name = (
                        cookie.split(
                            "=",
                            1
                        )[0]
                    )

                    flags = []

                    if re.search(
                        r";\s*Secure\b",
                        cookie,
                        re.I
                    ):
                        flags.append("Secure")

                    if re.search(
                        r";\s*HttpOnly\b",
                        cookie,
                        re.I
                    ):
                        flags.append("HttpOnly")

                    if re.search(
                        r";\s*SameSite=",
                        cookie,
                        re.I
                    ):
                        flags.append("SameSite")

                    print(
                        f"  {cookie_name}: "
                        f"{', '.join(flags) or 'No security flags detected'}"
                    )

            else:
                print(
                    "  No Set-Cookie header"
                )

        except Exception as exc:

            print(
                "HTTP inspection failed:",
                exc
            )


# ============================================================
# BASIC TECHNOLOGY HINTS
# ============================================================

def technology_hints(domain):

    heading("WEB TECHNOLOGY HINTS")

    try:

        url = f"https://{domain}/"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":
                    "Mozilla/5.0 Authorized-Recon/3.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT
        ) as response:

            headers = response.headers

            server = headers.get(
                "Server",
                ""
            )

            powered = headers.get(
                "X-Powered-By",
                ""
            )

            via = headers.get(
                "Via",
                ""
            )

            if server:
                print(
                    " - Server header:",
                    server
                )

            if powered:
                print(
                    " - X-Powered-By:",
                    powered
                )

            if via:
                print(
                    " - Via:",
                    via
                )

            if not any(
                (server, powered, via)
            ):
                print(
                    " - No obvious technology "
                    "headers disclosed."
                )

    except Exception as exc:

        print(
            "Technology detection failed:",
            exc
        )


# ============================================================
# TCP PORT SCAN
# ============================================================

def scan_port(ip, port):

    try:

        with socket.create_connection(
            (ip, port),
            timeout=TIMEOUT
        ):

            try:
                service = socket.getservbyport(
                    port,
                    "tcp"
                )
            except OSError:
                service = "unknown"

            return port, service

    except Exception:
        return None


def port_scan(ip):

    heading(
        f"COMMON TCP PORTS: {ip}"
    )

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=THREADS
    ) as executor:

        futures = [
            executor.submit(
                scan_port,
                ip,
                port
            )
            for port in COMMON_PORTS
        ]

        for future in concurrent.futures.as_completed(
            futures
        ):

            result = future.result()

            if result:
                results.append(result)

    results.sort()

    if not results:

        print(
            "No open common TCP ports detected."
        )
        return

    for port, service in results:

        print(
            f"{port:>5}/tcp  "
            f"{service:<15} OPEN"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\nAdvanced Recon Scanner v3"
    )

    raw = input(
        "Enter domain or URL: "
    )

    try:

        domain = clean_domain(raw)

    except ValueError as exc:

        print("Error:", exc)
        return

    print(
        f"\nTarget: {domain}"
    )

    # IP resolution
    ips = resolve_ips(domain)

    heading("IP ADDRESSES")

    if not ips:

        print(
            "Domain did not resolve."
        )
        return

    for ip in ips:
        print(" ", ip)

    # Registration
    whois_lookup(domain)
    rdap_lookup(domain)

    # DNS
    dns_lookup(domain)
    mail_security(domain)

    # TLS
    tls_lookup(domain)

    # Web
    http_lookup(domain)
    technology_hints(domain)

    # IP + ports
    for ip in ips:

        ip_information(ip)
        port_scan(ip)

    heading("SCAN COMPLETE")

    print(
        "No report file was created."
    )


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:

        print(
            "\n\nScan interrupted by user."
        )