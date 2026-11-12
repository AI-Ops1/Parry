import subprocess
def ping_host(host: str):
    return subprocess.run(f'ping -c 1 {host}', shell=True)
