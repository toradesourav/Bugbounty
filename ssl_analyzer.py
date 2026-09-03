#!/usr/bin/env python3
"""
SSL Certificate Analyzer
--------------------------
Connects to a host:port over TLS and analyzes the presented
certificate: expiry (and days remaining), issuer, subject, Subject
Alternative Names, signature algorithm, and self-signed detection.
Also flags weak/deprecated TLS protocol versions if the server
negotiates one.

Note: Python's ssl.getpeercert() returns an EMPTY dict for any
certificate that isn't independently verified (self-signed, expired,
wrong hostname, etc.) -- which is exactly the kind of cert this tool
most wants to inspect. To handle that, this tool always pulls the raw
DER certificate bytes and parses them directly with the `cryptography`
library, regardless of validation status.

Requires: pip install cryptography

Usage:
    python ssl_analyzer.py --host target.com
    python ssl_analyzer.py --host target.com --port 8443
"""

import argparse
import datetime
import socket
import ssl
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[!] This tool requires the 'cryptography' package: pip install cryptography", file=sys.stderr)
    sys.exit(1)

WEAK_SIG_ALGORITHMS = ["md5", "sha1"]
DEPRECATED_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def get_der_certificate(host, port, timeout):
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            protocol = ssock.version()
            cipher = ssock.cipher()
            return der_cert, protocol, cipher


def get_common_name(name_obj):
    try:
        attrs = name_obj.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Analyze the TLS certificate presented by a host.")
    parser.add_argument("--host", required=True, help="Hostname to connect to, e.g. target.com")
    parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")
    args = parser.parse_args()

    print(f"[*] Connecting to {args.host}:{args.port}...")
    try:
        der_cert, protocol, cipher = get_der_certificate(args.host, args.port, args.timeout)
    except (socket.timeout, socket.gaierror, ConnectionError, ssl.SSLError, OSError) as e:
        print(f"[!] Connection/TLS handshake failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not der_cert:
        print("[!] No certificate was presented by the server.", file=sys.stderr)
        sys.exit(1)

    cert = x509.load_der_x509_certificate(der_cert, default_backend())

    print("-" * 60)
    print(f"[*] TLS protocol negotiated: {protocol}")
    if protocol in DEPRECATED_TLS_VERSIONS:
        print(f"    [!] DEPRECATED protocol -- should be disabled server-side (modern minimum: TLSv1.2)")

    if cipher:
        cipher_name, tls_version, bits = cipher
        print(f"[*] Cipher suite: {cipher_name} ({bits}-bit)")

    subject_cn = get_common_name(cert.subject)
    issuer_cn = get_common_name(cert.issuer)
    print(f"\n[*] Subject CN: {subject_cn or 'N/A'}")
    print(f"[*] Issuer CN: {issuer_cn or 'N/A'}")

    if subject_cn and subject_cn == issuer_cn:
        print("    [!] Subject and Issuer CN match -- this looks SELF-SIGNED.")

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
        if san_list:
            shown = ", ".join(san_list[:10]) + (" ..." if len(san_list) > 10 else "")
            print(f"[*] Subject Alternative Names ({len(san_list)}): {shown}")
    except x509.ExtensionNotFound:
        print("[*] No Subject Alternative Name extension found (relying on CN alone -- deprecated practice)")

    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after

    print(f"\n[*] Valid from: {not_before}")
    print(f"[*] Valid until: {not_after}")

    now = datetime.datetime.now(datetime.timezone.utc) if not_after.tzinfo else datetime.datetime.utcnow()
    remaining = (not_after - now).days

    if remaining < 0:
        print(f"    [!!! EXPIRED] certificate expired {abs(remaining)} day(s) ago")
    elif remaining < 14:
        print(f"    [!] EXPIRES SOON -- only {remaining} day(s) remaining")
    elif remaining < 30:
        print(f"    [*] {remaining} day(s) remaining -- renew soon")
    else:
        print(f"    [OK] {remaining} day(s) remaining")

    sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    print(f"\n[*] Signature algorithm: {sig_algo}")
    if sig_algo.lower() in WEAK_SIG_ALGORITHMS:
        print(f"    [!] WEAK signature algorithm -- should be upgraded to SHA-256 or better")

    print(f"[*] Serial number: {cert.serial_number}")


if __name__ == "__main__":
    main()
