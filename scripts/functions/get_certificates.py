import ssl
import socket
import datetime

def get_ssl_certificate_info_primary(hostname, port=443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        
        issuer = dict(x[0] for x in cert.get('issuer', []))
        issued_by = issuer.get('organizationName', 'Unknown')

        not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        ttl_days = (not_after - datetime.datetime.utcnow()).days


    except ssl.SSLCertVerificationError:
        issued_by = None
        ttl_days = 0

    except Exception as e:
        issued_by = None
        ttl_days = 0

    return {
        "Certificate_Issuer": issued_by,
        "Certificate_TTL": ttl_days,
    }



def get_ssl_certificate_info_secondary(hostname, port=443):
    # If the first method can't find CA, try this one

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs()

    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert = sslsock.getpeercert()
                
                if not cert:
                    return {'Certificate_Issuer': None, 'Certificate_TTL': 0}

                issuer = cert.get("issuer", [])
                issued_by = None
                if isinstance(issuer, list):
                    for field in issuer:
                        if isinstance(field, tuple) and field[0][0] == 'organizationName':
                            issued_by = field[0][1]
                            break
                
                if not issued_by:
                    issued_by = None  

                not_after_str = cert.get("notAfter")
                ttl_days = 0
                if not_after_str:
                    try:
                        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        not_after = not_after.replace(tzinfo=datetime.UTC)
                        now = datetime.datetime.now(datetime.UTC)
                        ttl_days = (not_after - now).days
                    except ValueError:
                        ttl_days = 0

                return {
                    "Certificate_Issuer": issued_by,
                    "Certificate_TTL": ttl_days,
                }

    except Exception:
        return {'Certificate_Issuer': None, 'Certificate_TTL': 0}


def get_ssl_certificate_info(hostname):
    cert_info = get_ssl_certificate_info_primary(hostname, 443)

    if cert_info['Certificate_Issuer'] is None and cert_info['Certificate_TTL'] in [0, None]:
        cert_info = get_ssl_certificate_info_secondary(hostname, 443)

    return cert_info


