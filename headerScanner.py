import requests

def scan_headers(url):

    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]

    missing_headers = []

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)

    except Exception as e:
        print("Header scan error:", e)

    return missing_headers
