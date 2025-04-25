import argparse
import time
import pandas as pd
import numpy as np
import joblib
import shap


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
            print(f"The domain {domain} could not be resolved to a valid IPv4 address. Skipping.")
            return None
        ip_as_int, spf_status, mx_status, dkim_status, dmarc_status = DNS_data[2:]
        


        # === SSL Certificate Data ===
        print("\n== Fetching SSL certificate data ==")
        SSL = get_ssl_certificate_info(domain)
        cert_issuer = SSL.get("Certificate_Issuer") or "Unknown"
        cert_ttl = SSL.get("Certificate_TTL")
        cert_ttl = cert_ttl if isinstance(cert_ttl, int) and cert_ttl >= 0 else -1
        validity_length = SSL.get("Validity_Length")
        validity_length = validity_length if isinstance(validity_length, int) and validity_length >= 0 else -1
        san_count = SSL.get("SAN_Count")
        san_count = san_count if isinstance(san_count, int) and san_count >= 0 else -1


        # === Whois Data ===
        print("\n== Obtaining Whois data ==")
        try:
            whois_info = who_is(domain)
            registrar = whois_info[0] or "Unknown"
            creation_date = whois_info[1] if whois_info[1] != -1 else -1
            update_date = whois_info[2] if whois_info[2] != -1 else -1
            reg_period = whois_info[3] if len(whois_info) > 3 and isinstance(whois_info[3], int) else -1
            time.sleep(3)
        except Exception as e:
            print(f"Error fetching WHOIS data: {e}")
            registrar, creation_date, update_date, reg_period = "Unknown", -1, -1, -1

        # === ASN Data ===
        print("\n == Fetching ASN data ==")
        A_record_ip = A_record[0] if A_record and isinstance(A_record, list) else None
        AS_value = get_asn(A_record_ip)
        AS_value = int(AS_value) if AS_value is not None else -1


        # === HTTP Header Data ===
        print("\n == Fetching HTTP headers data ==")
        http_status = get_http_status(f"http://{domain}")
        headers = get_header_info(f"http://{domain}")
        server = headers or "Unknown"

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
            "Registration_Period": reg_period,
            "SSL_Issuer": cert_issuer,
            "SSL_TTL": cert_ttl,
            "Validity_Length": validity_length,
            "SAN_Count": san_count,
            "IPv4_Num": ip_as_int,
            "NumOfIPs": num_ips, 
            "SPF": int(spf_status),
            "MX": int(mx_status),
            "DKIM": int(dkim_status),
            "DMARC": int(dmarc_status),
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
            "Is_Unicode": int(is_unicode),
            "Levenshtein_Distance": levenshtein_dist,
            "Contains_Blacklisted": int(contains_blacklisted),
            "Last_is_sk": int(check_last),
            "Location": location_data,
        }
    
    except Exception as e:
        print(f"Error scanning {domain}: {e}")
        return None

# Logistic Regression, Random Forest and XGBoost

def get_shap_importance(model, model_name, scaled_features):
    explainer = shap.Explainer(model, scaled_features)
    shap_values = explainer(scaled_features)
    values = shap_values.values[0]  # First (and only) sample
    feature_importance = list(zip(scaled_features.columns, values))
    feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
    return {
        "model": model_name,
        "features": feature_importance[:10]  # Return top 10
    }

def classify_with_models(domain, log_reg, rf, xgb, scaler, target_encodings, global_mean):
    features = scan_domain(domain)
    if features is None:
        return {
            "domain": domain,
            "result": "SCAN_FAILED",
            "shap": []
        }

    for key in features:
        if isinstance(features[key], bool):
            features[key] = int(features[key])

    domain_df = pd.DataFrame([features])
    domain_df.drop(columns=["Domain"], inplace=True)

    for col in ["Registrar", "SSL_Issuer", "Server", "Location"]:
        if col in domain_df.columns:
            domain_df[col] = domain_df[col].map(target_encodings[col]).fillna(global_mean)

    scaled_features = pd.DataFrame(scaler.transform(domain_df), columns=domain_df.columns)

    # Predikcie
    log_pred = log_reg.predict(scaled_features)[0]
    rf_pred = rf.predict(scaled_features)[0]
    xgb_pred = xgb.predict(scaled_features)[0]

    final_pred = np.mean([log_pred, rf_pred, xgb_pred])
    final_class = 1 if final_pred >= 0.5 else 0

    shap_results = [
        get_shap_importance(log_reg, "Logistic Regression", scaled_features),
        get_shap_importance(rf, "Random Forest", scaled_features),
        get_shap_importance(xgb, "XGBoost", scaled_features)
    ]

    return {
        "domain": domain,
        "result": "MALICIOUS" if final_class == 1 else "BENIGN",
        "shap": shap_results
    }


# ARGPARSE INPUT
def main():
    parser = argparse.ArgumentParser(description="Classify a domain as malicious or benign.")
    parser.add_argument("domain", type=str, help="Input a domain (e.g. upjs.sk) to classify it.")
    args = parser.parse_args()

    log_reg = joblib.load("scripts\\classification\\models\\log_reg_model.pkl")
    rf = joblib.load("scripts\\classification\\models\\rf_model.pkl")
    xgb = joblib.load("scripts\\classification\\models\\xgb_model.pkl")
    target_encodings = joblib.load("scripts\\classification\\models\\target_encodings.pkl")
    global_mean = joblib.load("scripts\\classification\\models\\global_mean.pkl")
    scaler = joblib.load("scripts\\classification\\models\\scaler.pkl")

    result = classify_with_models(args.domain, log_reg, rf, xgb, scaler, target_encodings, global_mean)

    print(f"\n=== Classification Results for {result['domain']} ===")
    if result["result"] == "SCAN_FAILED":
        print("Domain could not be scanned.")
        return

    print(f"Classification: {result['result']}")
    print("\n--- Top SHAP Features ---")
    for model_info in result["shap"]:
        print(f"\nModel: {model_info['model']}")
        for name, val in model_info["features"]:
            print(f"{name}: {val:.4f}")


if __name__ == "__main__":
    main()