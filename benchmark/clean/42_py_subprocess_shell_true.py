import subprocess
def ping_host(host: str):
    return subprocess.run(['ping', '-c', '1', host], shell=False, check=True)
