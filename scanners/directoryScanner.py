import requests

COMMON_DIRS = [
    "admin", "login", "backup", "uploads",
    "config", "dashboard", ".git", "test"
]

def scan_directories(base_url):
    found = []

    for d in COMMON_DIRS:
        url = f"{base_url.rstrip('/')}/{d}"

        try:
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                found.append(url)
        except:
            pass

    return found