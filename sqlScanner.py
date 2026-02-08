import requests

def scan_sql_injection(urls):
    payload = "' OR '1'='1"
    vulnerable_urls = []

    for url in urls:
        try:
            test_url = url + payload
            response = requests.get(test_url, timeout=5)

            content = response.text.lower()

            # Common SQL error keywords
            if (
                "sql" in content or
                "mysql" in content or
                "syntax error" in content or
                "warning" in content
            ):
                vulnerable_urls.append(url)

        except Exception:
            # Ignore broken links or timeouts
            pass

    return vulnerable_urls
