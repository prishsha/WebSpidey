import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def scan_open_redirect(urls):
    vulnerable = []

    test_payload = "https://evil.com"

    for url in urls:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        for param in query:
            test_query = query.copy()
            test_query[param] = test_payload

            new_query = urlencode(test_query, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                res = requests.get(test_url, allow_redirects=False, timeout=3)

                if res.status_code in [301, 302]:
                    location = res.headers.get("Location", "")
                    if "evil.com" in location:
                        vulnerable.append(test_url)

            except:
                pass

    return vulnerable