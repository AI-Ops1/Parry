import requests_cache
def install():
    requests_cache.install_cache('app_cache', backend='redis')
