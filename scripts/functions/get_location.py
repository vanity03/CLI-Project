import requests

# mapa na normalizaciu nazvov - niekedy sluzba vratila The Netherlands namiesto Netherlands, tak nech je to jednotne
COUNTRY_NORMALIZATION = {
    "The Netherlands": "Netherlands",
    "Czech Republic": "Czechia",
    "Republic of Korea": "South Korea",
    "Russian Federation": "Russia",
    "United Kingdom": "UK",
    "United States": "USA",


    # miesto na pridavanie dalsich, ak si vsimneme chybu
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
