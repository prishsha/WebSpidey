import requests

def scan_xss(urls):
    """
    Performs basic reflected XSS detection
    """

    payload = "<script>alert(1)</script>"
    vulnerable_urls = []

    for url in urls:
        try:
            test_url = url + "?test=" + payload
            response = requests.get(test_url, timeout=5)

            # If payload is reflected back, XSS may exist
            if payload in response.text:
                vulnerable_urls.append(url)

        except Exception:
            pass

    return vulnerable_urls
