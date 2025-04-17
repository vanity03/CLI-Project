import argparse
import time
import pandas as pd
import numpy as np
import joblib

# Import functions from other files
from scripts.functions.get_ASN import get_asn
from scripts.functions.get_certificates import get_ssl_certificate_info
from scripts.functions.get_dns import check_dns
from scripts.functions.get_headers import get_http_status, get_header_info
from scripts.functions.get_lexical import shannon_entropy, ratios, detect_unicode, levenshtein_distance, sequences, contains_word, last_bigram_is_sk
from scripts.functions.get_location import location
from scripts.functions.get_whois import who_is

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
        
        
        if AS_value is not None:
            AS_value = pd.to_numeric(AS_value, errors="coerce")



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
        }
    
    except Exception as e:
        print(f"Error scanning {domain}: {e}")
        return None

# Logistic Regression, Random Forest and XGBoost
def classify_with_models(domain, log_reg, rf, xgb, scaler, target_encodings, global_mean):
    features = scan_domain(domain)

    if features is None:
        return "Domain could not be scanned or features are missing"
    
    for key in features:
        if isinstance(features[key], bool):
            features[key] = int(features[key])

    domain_df = pd.DataFrame([features])

    domain_df.drop(columns=["Domain"], inplace=True)

    # TE
    for col in ["Registrar", "SSL_Issuer", "Server", "Location"]:
        if col in domain_df.columns:
            domain_df[col] = domain_df[col].map(target_encodings[col]).fillna(global_mean)

    unscaled_features = domain_df.copy()
    scaled_features = pd.DataFrame(scaler.transform(domain_df), columns=domain_df.columns)


    log_pred = log_reg.predict(scaled_features)[0] 
    rf_pred_unscaled = rf.predict(unscaled_features)[0] 
    xgb_pred_unscaled = xgb.predict(unscaled_features)[0]

    rf_pred_scaled = rf.predict(scaled_features)[0]  
    xgb_pred_scaled = xgb.predict(scaled_features)[0]  

    final_pred_unscaled = np.mean([log_pred, rf_pred_unscaled, xgb_pred_unscaled])
    final_class_unscaled = 1 if final_pred_unscaled >= 0.5 else 0

    final_pred_scaled = np.mean([log_pred, rf_pred_scaled, xgb_pred_scaled])
    final_class_scaled = 1 if final_pred_scaled >= 0.5 else 0

    # Return both results
    return {
        "Unscaled Data": "MALICIOUS" if final_class_unscaled == 1 else "BENIGN",
        "Scaled Data": "MALICIOUS" if final_class_scaled == 1 else "BENIGN"
    }

# ARGPARSE INPUT
def main():
    parser = argparse.ArgumentParser(description="Classify a domain as malicious or benign.")
    parser.add_argument("domain", type=str, help="Input a domain (ex. upjs.sk) to classify it.")

    # TODO: Add a way to process whole file of domains.
    # parser.add_argument("--file", type=str, help="Path to a file with a list of domains to classify.")

    args = parser.parse_args()

    # Models
    log_reg = joblib.load("scripts\\classification\\models\\log_reg_model.pkl")
    rf = joblib.load("scripts\\classification\\models\\rf_model.pkl")
    xgb = joblib.load("scripts\\classification\\models\\xgb_model.pkl")

    # Target Encoding stuff
    target_encodings = joblib.load("scripts\\classification\\models\\target_encodings.pkl")
    global_mean = joblib.load("scripts\\classification\\models\\global_mean.pkl")

    # Scaler for LR
    scaler = joblib.load("scripts\\classification\\models\\scaler.pkl")

    # One domain inputted
    if args.domain:
        domain = args.domain
        print(f"Classifying domain: {domain}")
        result = classify_with_models(args.domain, log_reg, rf, xgb, scaler, target_encodings, global_mean)

        print(f"\n=== Classification Results for {args.domain} ===")
        print(f"Domain: {domain} is {'MALICIOUS' if result == 1 else 'BENIGN'}.")

        print(f"Using UNscaled data (RF/XGB on raw features): {result['Unscaled Data']}")
        print(f"Using Scaled data (RF/XGB with normalization): {result['Scaled Data']}")

if __name__ == "__main__":
    main()