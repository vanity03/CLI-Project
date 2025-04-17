from scripts.functions.get_ASN import get_asn
from scripts.functions.get_certificates import get_ssl_certificate_info
from scripts.functions.get_dns import resolve_dns_record, resolve_with_retry, check_dns
from scripts.functions.get_headers import get_header_info, get_http_status
from scripts.functions.get_lexical import shannon_entropy, ratios, levenshtein_distance, detect_unicode
from scripts.functions.get_location import location
from scripts.functions.get_whois import who_is

def main(domain):
    used_port = 443
    dkim_selector = "default"
    w = open("whitelist.txt", "r")

    try:
        print(f"\n=== Scanning domain: {domain} ===\n")

        # === SSL Certificate Data ===
        print("\n== Fetching SSL certificate data ==")
        SSL = get_ssl_certificate_info(domain)
        print("SSL Certificate Issuer:", SSL["Certificate_Issuer"])
        print("SSL Certificate TTL:", SSL["Certificate_TTL"])


        # === Whois Data ===
        print("\n== Obtaining Whois data ==")
        whois_info = who_is(domain)
        registrar = whois_info[0]
        creation_date = whois_info[1]
        update_date = whois_info[2]

        print(registrar)
        print(creation_date)
        print(update_date)

        # === DNS Data ===
        print("\n== Obtaining DNS data ==")


        DNS_data = check_dns(domain)
        print(DNS_data)

        # === ASN Data ===
        print("\n== Fetching ASN data ==")
        ASN = get_asn(DNS_data["A_Record"][0])
        print("ASN:", ASN)



        # === HTTP Header Data ===
        print("\n == Fetching HTTP headers data ==")
        http_status = get_http_status(f"http://{domain}")
        headers = get_header_info(f"http://{domain}")
        print("HTTP Status:", http_status)
        print("Headers:", headers)

        # === Lexical Analysis ===
        print("\n == Lexical analysis ==")
        entropy = shannon_entropy(domain)
        vowel_ratio, consonant_ratio, numerical_ratio, special_char_ratio = ratios(domain)
        is_unicode = detect_unicode(domain)

        levenshtein_dist = levenshtein_distance(domain, w)
        print("Levenshtein Distance:", levenshtein_dist)
        print("Shannon Entropy:", entropy)
        print("Vowel Ratio:", vowel_ratio)
        print("Consonant Ratio:", consonant_ratio)
        print("Numerical Ratio:", numerical_ratio)
        print("Special Character Ratio:", special_char_ratio)
        print("Is Unicode:", is_unicode)



        # == Location Data ==
        print("\n == Obtaining location data. ==")
        location_data = location(domain)
        print("Location is:", location_data)
        print("\n=== Scan Completed for:", domain, "===\n")

    except Exception as e:
        print("Some error occurred:", str(e))


# Run the main function
if __name__ == "__main__":
    domain = "datart.sk"  # Change this domain to scan a different website
    main(domain)