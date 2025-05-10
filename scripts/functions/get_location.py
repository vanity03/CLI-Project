import requests


# map for normalizing names - sometimes the tool returned "The Netherlands" instead of "Netherlands", so this is added to unify the results
COUNTRY_NORMALIZATION = {
    "The Netherlands": "Netherlands",
    "Czech Republic": "Czechia",
    "Republic of Korea": "South Korea",
    "Russian Federation": "Russia",
    "United Kingdom": "UK",
    "United States": "USA",


    # place to add other
}

def location(domain):
    query = f"http://ip-api.com/json/{domain}"
    try:
        response = requests.get(query, timeout=5)
        if response.status_code == 200:
            country = response.json().get("country", "Unknown")
            return COUNTRY_NORMALIZATION.get(country, country) 
        else:
            return "Unknown"
    except Exception:
        return "Unknown"
