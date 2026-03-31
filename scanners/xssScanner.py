import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def scan_xss(url_list):
    payload = "<script>alert(1)</script>"
    vulnerable = []

    for url in url_list:
        try:
            # ---------------- FORM-BASED XSS ----------------
            res = requests.get(url)
            soup = BeautifulSoup(res.text, "html.parser")

            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")

                data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data[name] = payload

                if method == "post":
                    response = requests.post(url, data=data)
                else:
                    response = requests.get(url, params=data)

                if payload in response.text:
                    vulnerable.append(url)

            # ---------------- URL PARAMETER XSS ----------------
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if params:
                test_params = {k: payload for k in params}
                new_query = urlencode(test_params, doseq=True)

                test_url = urlunparse(parsed._replace(query=new_query))
                response = requests.get(test_url)

                if payload in response.text:
                    vulnerable.append(url)

        except Exception:
            continue

    return list(set(vulnerable))