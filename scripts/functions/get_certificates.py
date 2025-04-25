import ssl
import socket
import datetime

def get_ssl_certificate_info(hostname, port=443, timeout=5):
    def fetch(verify_hostname):
        ctx = ssl.create_default_context()
        ctx.check_hostname = verify_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        if not verify_hostname:
            ctx.load_default_certs()

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock,
                                    server_hostname=hostname if verify_hostname else None) as ssock:
                    cert = ssock.getpeercert()
        except Exception:
            return None, None, None, None, True  # ← PRIDANÉ

        if not cert:
            return "Unknown", -1, -1, 0, False   # ← SAN_COUNT = 0, error=False

        # === issuer ===
        issuer = None
        for rdn in cert.get('issuer', []):
            for key, val in rdn:
                if key == 'organizationName':
                    issuer = val
                    break
            if issuer:
                break
        if not issuer:
            issuer = "Unknown"

        # === TTL ===
        na = cert.get('notAfter')
        try:
            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            ttl = (exp - now).days
        except Exception:
            ttl = -1

        # === Validity Length ===
        nb = cert.get('notBefore')
        try:
            start = datetime.datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            validity = (exp - start).days
        except Exception:
            validity = -1

        # === SAN count ===
        san = cert.get("subjectAltName", [])
        san_count = len([entry for entry in san if entry[0] == "DNS"])

        return issuer, ttl, validity, san_count, False

    # 1. Prvý pokus
    result = fetch(verify_hostname=True)

    # 2. Ak chyba, fallback bez verifikácie hostname
    if result[-1]:  # chyba
        result = fetch(verify_hostname=False)
        if result[-1]:  # stále chyba
            return {
                "Certificate_Issuer": None,
                "Certificate_TTL": None,
                "Validity_Length": None,
                "SAN_Count": None
            }

    issuer, ttl, validity, san_count = result[:4]

    return {
        "Certificate_Issuer": issuer,
        "Certificate_TTL": ttl,
        "Validity_Length": validity,
        "SAN_Count": san_count
    }


