import dns.resolver
import time

dkim_selector = "default"

def resolve_dns_record(record_type, query):
    try:
        records = [dns_record.to_text() for dns_record in dns.resolver.resolve(query, record_type).rrset]
        return records
    except dns.resolver.NoAnswer:
        return []  
    except dns.resolver.NXDOMAIN:
        return [] 
    except dns.resolver.Timeout:
        return ["Timeout"] 
    except Exception as e:
        return [f"Error: {str(e)}"]  

def resolve_with_retry(record_type, query, retries=3):
    # Try again when timeouted
    for _ in range(retries):
        result = resolve_dns_record(record_type, query)
        if result != ["Timeout"]:
            return result
        time.sleep(1)  
    return ["null"]  

def split_ip(ip):
    """Split IP address into its individual parts."""
    return list(map(int, ip.split(".")))

def check_dns(domain):
     # A Record
    A_record = resolve_with_retry("A", domain)
    num_ips = len(A_record) if A_record not in (["null"], []) else 0

    # Skip further processing if no IP found
    if num_ips == 0:
        return A_record, num_ips, None, None, None, None, None, None, None, None, None

    # Splitting IP address to octets for dataset
    split_ip_address = None
    if A_record not in (["null"], []):
        first_ip = A_record[0]
        split_ip_address = split_ip(first_ip)
        
        if len(split_ip_address) == 4:
            first_octet = split_ip_address[0]
            second_octet = split_ip_address[1]
            third_octet = split_ip_address[2]
            fourth_octet = split_ip_address[3]
        else:
            first_octet = None
            second_octet = None
            third_octet = None
            fourth_octet = None

    # TXT Records 
    txt_records = resolve_with_retry("TXT", domain)
    txt_status = 1 if txt_records not in ([], ["0"]) else 0  

    # SPF Record 
    spf_record = [record for record in txt_records if "v=spf1" in record]
    spf_status = 1 if spf_record else 0  

    # MX 
    mx_records = resolve_with_retry("MX", domain)
    mx_status = 1 if mx_records not in ([], ["0"]) else 0  

    # DKIM 
    dkim_records = resolve_with_retry("TXT", f"{dkim_selector}._domainkey.{domain}")
    dkim_status = 1 if dkim_records not in ([], ["0"]) else 0  

    # DMARC
    dmarc_records = resolve_with_retry("TXT", f"_dmarc.{domain}")
    dmarc_status = 1 if dmarc_records not in ([], ["0"]) else 0  

    return A_record, num_ips, first_octet, second_octet, third_octet, fourth_octet, txt_status, spf_status, mx_status, dkim_status, dmarc_status


result = check_dns("basetools.sk")
print(result)