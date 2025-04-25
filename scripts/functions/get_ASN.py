from ipwhois import IPWhois

def get_asn(ip):
    if not ip:
        return None
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result.get("asn")  # string ako "12345"
    except Exception:
        return None

