import requests
from bs4 import BeautifulSoup

def scan_sql_injection(url_list):
    payload = "' OR '1'='1"
    normal_value = "test123"

    vulnerable = []

    for url in url_list:
        try:
            res = requests.get(url)
            soup = BeautifulSoup(res.text, "html.parser")

            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")

                normal_data = {}
                injected_data = {}

                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        normal_data[name] = normal_value
                        injected_data[name] = payload

                # send normal request
                if method == "post":
                    normal_res = requests.post(url, data=normal_data)
                    injected_res = requests.post(url, data=injected_data)
                else:
                    normal_res = requests.get(url, params=normal_data)
                    injected_res = requests.get(url, params=injected_data)

                normal_text = normal_res.text.lower()
                injected_text = injected_res.text.lower()

                #  Detection Method 1: Error-Based 
                if "sql" in injected_text or "syntax" in injected_text:
                    vulnerable.append(url)
                    continue

                #  Detection Method 2: Response Difference 
                if len(injected_text) != len(normal_text):
                    diff = abs(len(injected_text) - len(normal_text))

                    if diff > 50:  # threshold to avoid noise
                        vulnerable.append(url)

        except Exception:
            continue

    return list(set(vulnerable))