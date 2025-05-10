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
            return None, None

        if not cert:
            return "Unknown", -1

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

    # 1. first try with verifying hostname
    result = fetch(verify_hostname=True)

    # 2. error - if fails, we try without verifying hostname
    if result[-1]:  # chyba
        result = fetch(verify_hostname=False)
        if result[-1]:
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


