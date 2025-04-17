import time
import pandas as pd

# Import functions from other files
from scripts.functions.get_ASN import get_asn
from scripts.functions.get_certificates import get_ssl_certificate_info
from scripts.functions.get_dns import check_dns
from scripts.functions.get_headers import get_header_info, get_http_status
from scripts.functions.get_lexical import shannon_entropy, ratios, levenshtein_distance, detect_unicode, sequences, contains_word, last_bigram_is_sk
from scripts.functions.get_location import location
from scripts.functions.get_whois import who_is


# File processing
def load_domains_from_file(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()} 
    except FileNotFoundError:
        print(f"Warning: {filename} not found.")
        return set()
    
good = load_domains_from_file("lists\\benign.txt")
bad = load_domains_from_file("lists\\malicious.txt")
# mix = load_domains_from_file("lists\\smaller_list.txt")
mix = load_domains_from_file("lists\\all.txt")


def classify_domain(domain):
    if domain in good:
        return 0
    elif domain in bad:
        return 1
    else:
        return -1

def scan_domain(domain):
    w = "lists\\whitelist.txt"
    b = "lists\\blacklist.txt"

    try:
        print(f"\n=== Scanning domain: {domain} ===\n")

        # === DNS Data ===
        print("\n== Obtaining DNS data ==")


        DNS_data = check_dns(domain)
        
        A_record, num_ips = DNS_data[:2] 
        
        if num_ips == 0:
            print(f"Skipping domain {domain} as no IP address was found.")
            return None
        
        first_octet, second_octet, third_octet, fourth_octet, txt_status, spf_status, mx_status, dkim_status, dmarc_status = DNS_data[2:]
        
        
        # === SSL Certificate Data ===
        print("\n== Fetching SSL certificate data ==")
        SSL = get_ssl_certificate_info(domain)
        cert_issuer = SSL.get("Certificate_Issuer")
        cert_ttl = SSL.get("Certificate_TTL")

        # === Whois Data ===
        print("\n== Obtaining Whois data ==")
        try:
            whois_info = who_is(domain)
            registrar = whois_info[0]
            creation_date = whois_info[1]
            update_date = whois_info[2]
            # Adding timeout btwn whois requests - to prevent blocking
            time.sleep(3)
        except Exception as e:
            print(f"Error fetching WHOIS data: {e}")
            registrar, creation_date, update_date = None, None, None

        # === ASN Data ===
        print("\n == Fetching ASN data ==")
        A_record_ip = A_record[0] if A_record and isinstance(A_record, list) else None
        AS_value = get_asn(A_record_ip) if A_record_ip else None

        # === HTTP Header Data ===
        print("\n == Fetching HTTP headers data ==")
        http_status = get_http_status(A_record_ip ,f"http://{domain}")
        headers = get_header_info(A_record_ip, f"http://{domain}")
        server, content = headers

        # === Lexical Analysis ===
        print("\n == Lexical analysis ==")
        entropy = shannon_entropy(domain)
        vowel_ratio, consonant_ratio, numerical_ratio, special_char_ratio = ratios(domain)
        is_unicode = detect_unicode(domain)
        levenshtein_dist = levenshtein_distance(domain, w)
        max_vowel_sequence, max_consonant_sequence, max_num_sequence, max_special_sequence = sequences(domain)
        contains_blacklisted = contains_word(domain, b)
        check_last = last_bigram_is_sk(domain)

        # == Location Data ==
        print("\n == Obtaining location data. ==")
        location_data = location(domain)

        # == Checking class ==
        maliciousness = classify_domain(domain)

        print("\n=== Scan Completed for:", domain, "===\n")

        
        return {
            "Domain": domain,
            "Registrar": registrar,
            "Creation_Date": creation_date,
            "Update_Date": update_date,
            "SSL_Issuer": cert_issuer,
            "SSL_TTL": cert_ttl,
            "First octet": first_octet,
            "Second octet": second_octet,
            "Third octet": third_octet,
            "Fourth octet": fourth_octet,
            "NumOfIPs": num_ips, 
            "TXTRecord": txt_status,
            "SPF": spf_status,
            "MX": mx_status,
            "DKIM": dkim_status,
            "DMARC": dmarc_status,
            "AS": AS_value,
            "HTTP_Status": http_status,
            "Server": server, 
            "Entropy": entropy,
            "Vowel_Ratio": vowel_ratio,
            "Consonant_Ratio": consonant_ratio,
            "Numerical_Ratio": numerical_ratio,
            "Special_Char_Ratio": special_char_ratio,
            "Vowel_Sequence": max_vowel_sequence,
            "Consonant_Sequence": max_consonant_sequence,
            "Numerical_Sequence": max_num_sequence,
            "Special_Char_Sequence": max_special_sequence,
            "Is_Unicode": is_unicode,
            "Levenshtein_Distance": levenshtein_dist,
            "Contains_Blacklisted": contains_blacklisted,
            "Last_is_sk": check_last,
            "Location": location_data,

            # 1 - malicious, 0 - benign
            "Class": maliciousness,
        }
    
    except Exception as e:
        print(f"Error scanning {domain}: {e}")
        return None


# Code to create dataset - loads each domain, for each does code above
def create_dataset(domains):
    data = []
    for domain in domains:
        result = scan_domain(domain)
        if result:
            data.append(result)

    df = pd.DataFrame(data)
    df.to_csv("scripts\\classification\\datasets\\new_dataset2.csv", index=False, na_rep="None")
    print("Dataset saved as new_dataset2.csv")


if __name__ == "__main__":
    domains = mix
    create_dataset(domains)