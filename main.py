import argparse
import time
import pandas as pd
import numpy as np
import joblib
import shap
from sklearn.pipeline import Pipeline

from scripts.functions.get_ASN import get_asn
from scripts.functions.get_certificates import get_ssl_certificate_info
from scripts.functions.get_dns import check_dns
from scripts.functions.get_headers import get_http_status, get_header_info
from scripts.functions.get_lexical import shannon_entropy, ratios, detect_unicode, levenshtein_distance, sequences, contains_word, last_bigram_is_sk
from scripts.functions.get_location import location
from scripts.functions.get_whois import who_is


def scan_domain(domain):
    w = "lists/whitelist.txt"
    b = "lists/blacklist.txt"

    try:
        print(f"\n=== Scanning domain: {domain} ===\n")

        # === DNS Data ===
        DNS_data = check_dns(domain)
        A_record, num_ips = DNS_data[:2]
        if num_ips == 0:
            print(f"The domain {domain} could not be resolved to a valid IPv4 address. Skipping.")
            return None
        ip_as_int, spf_status, mx_status, dkim_status, dmarc_status = DNS_data[2:]

        # === SSL Certificate Data ===
        SSL = get_ssl_certificate_info(domain)
        cert_issuer = SSL.get("Certificate_Issuer") or "Unknown"
        cert_ttl = SSL.get("Certificate_TTL") if isinstance(SSL.get("Certificate_TTL"), int) else -1


        # === Whois Data ===
        try:
            whois_info = who_is(domain)
            registrar = whois_info[0] or "Unknown"
            creation_date = whois_info[1] if whois_info[1] != -1 else -1
            update_date = whois_info[2] if whois_info[2] != -1 else -1
            time.sleep(3)
        except Exception as e:
            print(f"Error fetching WHOIS data: {e}")
            registrar, creation_date, update_date = "Unknown", -1, -1

        # === ASN Data ===
        A_record_ip = A_record[0] if A_record and isinstance(A_record, list) else None
        AS_value = get_asn(A_record_ip)
        AS_value = int(AS_value) if AS_value is not None else -1

        # === HTTP Header Data ===
        http_status = get_http_status(f"http://{domain}")
        headers = get_header_info(f"http://{domain}")
        server = headers or "Unknown"

        # === Lexical Analysis ===
        entropy = shannon_entropy(domain)
        vowel_ratio, consonant_ratio, numerical_ratio, special_char_ratio = ratios(domain)
        is_unicode = detect_unicode(domain)
        levenshtein_dist = levenshtein_distance(domain, w)
        max_vowel_sequence, max_consonant_sequence, max_num_sequence, max_special_sequence = sequences(domain)
        contains_blacklisted = contains_word(domain, b)
        check_last = last_bigram_is_sk(domain)

        # == Location Data ==
        location_data = location(domain)

        print(f"\n=== Scan Completed for: {domain} ===\n")

        return {
            "Domain": domain,
            "Registrar": registrar,
            "Creation_Date": creation_date,
            "Update_Date": update_date,
            "SSL_Issuer": cert_issuer,
            "SSL_TTL": cert_ttl,
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


def explain_single(domain_df, pipe, background, model_type="linear"):
    model = pipe.named_steps["model"]

    if model_type == "linear":
        scaler = pipe.named_steps["scale"]
        scaled_background = pd.DataFrame(scaler.transform(background), columns=background.columns)
        scaled_domain = pd.DataFrame(scaler.transform(domain_df), columns=domain_df.columns)

        masker = shap.maskers.Independent(scaled_background)
        explainer = shap.LinearExplainer(model, masker=masker)
        shap_vals = explainer(scaled_domain)

    elif model_type == "tree":
        # SHAP for tree models works best on unscaled numerical input
        background = background.astype(float)
        domain_df = domain_df.astype(float)

        explainer = shap.TreeExplainer(model, data=background)
        shap_vals = explainer(domain_df)

    else:
        raise ValueError(f"Unsupported model_type={model_type}")

    pred_class = model.predict(domain_df)[0]

    if shap_vals.values.ndim == 3:
        vals = shap_vals.values[0, pred_class, :]

    else:
        vals = shap_vals.values[0, :]

    values = sorted(
        zip(domain_df.columns, vals),
        key=lambda x: abs(x[1]),
        reverse=True
    )

    return values




def classify_with_models(domain, log_pipe, rf_pipe, xgb_pipe, target_encodings, global_mean, background):
    features = scan_domain(domain)
    if features is None:
        return {"domain": domain, "result": "SCAN_FAILED", "shap": {}}

    domain_df = pd.DataFrame([features])
    domain_df.drop(columns=["Domain"], inplace=True)

    # Target encoding
    for col in ["Registrar", "SSL_Issuer", "Server", "Location"]:
        if col in domain_df.columns:
            domain_df[col] = domain_df[col].map(target_encodings[col]).fillna(global_mean)

    
    expected_columns = background.columns.tolist()
    missing = set(expected_columns) - set(domain_df.columns)
    for col in missing:
        domain_df[col] = global_mean 

    domain_df = domain_df[expected_columns]
    domain_df = domain_df.astype(float)

    votes = [
        log_pipe.predict(domain_df)[0],
        rf_pipe.predict(domain_df)[0],
        xgb_pipe.predict(domain_df)[0]
    ]
    final = 1 if np.mean(votes) >= 0.5 else 0

    shap_results = {
        "Logistic Regression": explain_single(domain_df, log_pipe, background, model_type="linear"),
        "Random Forest": explain_single(domain_df, rf_pipe, background, model_type="tree"),
        "XGBoost": explain_single(domain_df, xgb_pipe, background, model_type="tree"),
    }

    return {
        "domain": domain,
        "result": "MALICIOUS" if final else "BENIGN",
        "shap": shap_results
    }




def main():
    parser = argparse.ArgumentParser(description="Classify a domain as malicious or benign.")
    parser.add_argument("domain", type=str, help="Input a domain (e.g. upjs.sk) to classify.")
    args = parser.parse_args()

    log_reg = joblib.load("scripts/classification/models/log_reg_model.pkl")
    rf = joblib.load("scripts/classification/models/rf_model.pkl")
    xgb = joblib.load("scripts/classification/models/xgb_model.pkl")
    target_encodings = joblib.load("scripts/classification/models/target_encodings.pkl")
    global_mean = joblib.load("scripts/classification/models/global_mean.pkl")
    scaler = joblib.load("scripts/classification/models/scaler.pkl")

    X_train = pd.read_csv("scripts/classification/datasets/dataset.csv")

    # Remove class and domain
    X_train = X_train.drop(columns=["Domain", "Class"])

    # Target Encoding
    for col in ["Registrar", "SSL_Issuer", "Server", "Location"]:
        if col in X_train.columns:
            X_train[col] = X_train[col].map(target_encodings[col]).fillna(global_mean)


    background = X_train.sample(n=100, random_state=42)


    log_pipe = Pipeline([("scale", scaler), ("model", log_reg)])
    rf_pipe = Pipeline([("scale", scaler), ("model", rf)])
    xgb_pipe = Pipeline([("scale", scaler), ("model", xgb)])

    result = classify_with_models(args.domain, log_pipe, rf_pipe, xgb_pipe, target_encodings, global_mean, background)

    print(f"\n=== Classification Results for {result['domain']} ===")
    if result['result'] == "SCAN_FAILED":
        print("Domain could not be scanned.")
        return

    print(f"Classification: {result['result']}")
    print("\n--- Top SHAP Features ---")
    for model_name, top10 in result['shap'].items():
        print(f"\nModel: {model_name}")
        for name, val in top10:
            print(f"  {name}: {val:.4f}")


if __name__ == "__main__":
    main()
