from ipwhois import IPWhois

def get_asn(ip):
    if not ip:
        return None
    
    obj = IPWhois(ip)
    result = obj.lookup_rdap()
    return result.get("asn")


