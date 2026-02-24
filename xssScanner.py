import requests
from bs4 import BeautifulSoup

def scan_xss(url_list):
    payload = "<script>alert(1)</script>"
    vulnerable = []

    for url in url_list:
        try:
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

        except Exception:
            continue

    return list(set(vulnerable))