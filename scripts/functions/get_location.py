import requests

def location(domain):
    # ip-api API
    query = f"http://ip-api.com/json/{domain}"
    response = requests.get(query)
    if response.status_code == 200:
        data = response.json() 
        return data.get("country", None)
    else:
        return None
