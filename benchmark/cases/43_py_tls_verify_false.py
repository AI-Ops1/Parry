import requests
def fetch_data(endpoint: str):
    return requests.get(endpoint, verify=False).json()
