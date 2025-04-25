import requests
import time

def get_http_status(url, max_retries=3, timeout=5):

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=timeout)
            return response.status_code
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)  

    return 0  

def get_header_info(url, max_retries=3, timeout=5):

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=timeout)
            server_info = response.headers.get("Server", None)
            return server_info
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)  

    return None 

