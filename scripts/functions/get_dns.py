import dns.resolver
import time

dkim_selector = "default"

def resolve_dns_record(record_type, query):
    try:
        records = [r.to_text() for r in dns.resolver.resolve(query, record_type).rrset]
        return records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.resolver.Timeout:
        return ["Timeout"]
    except Exception:
        return ["Error"]

def resolve_with_retry(record_type, query, retries=3):
    for _ in range(retries):
        result = resolve_dns_record(record_type, query)
        if result != ["Timeout"]:
            return result
        time.sleep(1)
    return ["null"]

def ip_to_int(ip):
    try:
        parts = list(map(int, ip.split(".")))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    except Exception:
        return None

def check_dns(domain):
    # A record
    a_record = resolve_with_retry("A", domain)
    num_ips = len(a_record) if a_record not in (["null"], []) else 0

    if num_ips == 0:
        return a_record, num_ips, None, 0, 0, 0, 0

    ip_as_int = ip_to_int(a_record[0]) if a_record not in (["null"], []) else None

    # TXT records
    txt_records = resolve_with_retry("TXT", domain)

    # SPF
    spf_present = any("v=spf1" in record.lower() for record in txt_records)
    spf_status = int(spf_present)

    # MX
    mx_records = resolve_with_retry("MX", domain)
    mx_status = int(mx_records not in ([], ["0"], ["Timeout"], ["Error"]))

    # DKIM
    dkim_query = f"{dkim_selector}._domainkey.{domain}"
    dkim_records = resolve_with_retry("TXT", dkim_query)
    dkim_status = int(dkim_records not in ([], ["0"], ["Timeout"], ["Error"]))

    # DMARC
    dmarc_query = f"_dmarc.{domain}"
    dmarc_records = resolve_with_retry("TXT", dmarc_query)
    dmarc_status = int(dmarc_records not in ([], ["0"], ["Timeout"], ["Error"]))

    return a_record, num_ips, ip_as_int, spf_status, mx_status, dkim_status, dmarc_status

# # Example call
# result = check_dns("basetools.sk")
# print(result)