import requests
import re

def scan_sensitive_data(urls):
    findings = []

    patterns = {
        "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "API Key": r"(?i)api[_-]?key\s*=\s*[A-Za-z0-9]+",
        "Token": r"(?i)token\s*=\s*[A-Za-z0-9]+"
    }

    for url in urls:
        try:
            res = requests.get(url, timeout=3)
            content = res.text

            for name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        "url": url,
                        "type": name,
                        "matches": matches[:3]  # limit output
                    })

        except:
            pass

    return findings