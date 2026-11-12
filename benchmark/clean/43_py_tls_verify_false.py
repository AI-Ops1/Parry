import requests
def fetch_data(endpoint: str):
    return requests.get(endpoint, timeout=10).json()
